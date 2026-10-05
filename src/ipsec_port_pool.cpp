/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *  Collision-free pool of UE protected ports (3GPP TS 33.203).
 *  Compiled without USE_IPSEC as well so the unit tests run in every build.
 */

#include "ipsec_port_pool.hpp"

IPSecPortPool::IPSecPortPool(uint16_t min_port, uint16_t max_port)
    : min_(min_port),
      used_(max_port >= min_port ? (size_t)(max_port - min_port) + 1 : 0, false),
      next_(0),
      in_use_(0)
{
}

uint16_t IPSecPortPool::acquire()
{
    /* Next-fit: continue after the last port handed out instead of taking the
     * lowest free one. A just-released port is then reused as late as possible,
     * while the P-CSCF may still hold the old SA for that UE ip:port. */
    size_t n = used_.size();
    for (size_t i = 0; i < n; i++) {
        size_t idx = (next_ + i) % n;
        if (!used_[idx]) {
            used_[idx] = true;
            in_use_++;
            next_ = (idx + 1) % n;
            return (uint16_t)(min_ + idx);
        }
    }
    return 0;
}

bool IPSecPortPool::release(uint16_t port)
{
    if (port < min_ || (size_t)(port - min_) >= used_.size())
        return false;
    size_t idx = port - min_;
    if (!used_[idx])
        return false;
    used_[idx] = false;
    in_use_--;
    return true;
}

#ifdef GTEST
#include "gtest/gtest.h"
#include <set>

/* A duplicate port means the second UE on that source IP fails to bind its
 * protected socket, i.e. a generator-side registration failure that would be
 * misread as a platform failure. */
TEST(IPSecPortPool, HandsOutEveryPortOnceUntilFull) {
    IPSecPortPool pool(40000, 40999);
    std::set<uint16_t> seen;
    for (int i = 0; i < 1000; i++) {
        uint16_t p = pool.acquire();
        EXPECT_GE(p, 40000);
        EXPECT_LE(p, 40999);
        EXPECT_TRUE(seen.insert(p).second) << "port " << p << " handed out twice";
    }
    EXPECT_EQ(pool.in_use(), 1000u);
}

/* Exhaustion must be visible to the caller (0) instead of silently reusing a
 * port that is still bound by another UE. */
TEST(IPSecPortPool, ReturnsZeroWhenExhausted) {
    IPSecPortPool pool(50000, 50001);
    EXPECT_NE(pool.acquire(), 0);
    EXPECT_NE(pool.acquire(), 0);
    EXPECT_EQ(pool.acquire(), 0);
}

/* A released port must become available again, otherwise a long run with
 * de-registrations leaks the pool until no UE can register. */
TEST(IPSecPortPool, ReleasedPortIsReusable) {
    IPSecPortPool pool(50000, 50001);
    uint16_t a = pool.acquire();
    pool.acquire();
    EXPECT_TRUE(pool.release(a));
    EXPECT_EQ(pool.acquire(), a);
}

/* Next-fit: a just-released port is not handed straight back while other
 * ports are free, because the P-CSCF may still map it to the old SA. */
TEST(IPSecPortPool, DoesNotImmediatelyReuseReleasedPort) {
    IPSecPortPool pool(50000, 50009);
    uint16_t a = pool.acquire();
    EXPECT_TRUE(pool.release(a));
    EXPECT_NE(pool.acquire(), a);
}

/* A release path that runs twice, or a port that never came from the pool,
 * must not mark a port free that another UE still holds. */
TEST(IPSecPortPool, IgnoresDoubleAndForeignRelease) {
    IPSecPortPool pool(50000, 50009);
    uint16_t a = pool.acquire();
    EXPECT_TRUE(pool.release(a));
    EXPECT_FALSE(pool.release(a));
    EXPECT_FALSE(pool.release(49999));
    EXPECT_FALSE(pool.release(50010));
    EXPECT_EQ(pool.in_use(), 0u);
}

TEST(IPSecPortPool, CoversFullRange) {
    IPSecPortPool pool(32768, 65535);
    EXPECT_EQ(pool.capacity(), 32768u);
}
#endif
