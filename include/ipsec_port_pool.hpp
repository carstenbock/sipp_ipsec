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
 *  Collision-free pool of UE protected ports (port-c / port-s, 3GPP TS 33.203).
 *  Every concurrently registered UE on one source IP needs two ports of its
 *  own; handing out a port twice makes the second UE's bind() fail.
 */

#ifndef __IPSEC_PORT_POOL_HPP__
#define __IPSEC_PORT_POOL_HPP__

#include <stddef.h>
#include <stdint.h>
#include <vector>

class IPSecPortPool {
public:
    /* Pool over the inclusive range [min_port, max_port]. */
    IPSecPortPool(uint16_t min_port, uint16_t max_port);

    /* Returns a port not currently handed out, or 0 when the pool is exhausted. */
    uint16_t acquire();

    /* Returns the port to the pool. Ports outside the range or not handed out
     * are ignored and return false, so a double release cannot corrupt the pool. */
    bool release(uint16_t port);

    size_t in_use() const { return in_use_; }
    size_t capacity() const { return used_.size(); }

private:
    uint16_t min_;
    std::vector<bool> used_;
    size_t next_;
    size_t in_use_;
};

#endif /* __IPSEC_PORT_POOL_HPP__ */
