def __sendIcmpTraceRoute(self, host):
    print("sendIcmpTraceRoute Started...") if self.__DEBUG_IcmpHelperLibrary else 0
    # Build code for trace route here
    hops = 50
    attempts = 2
    limit = 2.0
    for hop in range(1, hops):
        for attempt in range(1, attempts):
            rawSocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
            rawSocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', hop))
            rawSocket.bind(('', 0))
            rawSocket.settimeout(limit)
            # print("looping before try")
            try:
                icmpPacket = IcmpHelperLibrary.IcmpPacket()
                randomIdentifier = (os.getpid() & 0xffff)
                icmpPacket.buildPacket_echoRequest(randomIdentifier, hop)
                header = struct.pack("BBHHH", 0, icmpPacket.getIcmpCode(), icmpPacket.getPacketChecksum(),
                                     icmpPacket.getPacketIdentifier(), hop)
                data = struct.pack("p", icmpPacket.getDataRaw().encode())
                packet = header + data
                icmpPacket.setIcmpTarget(host)
                # print(icmpPacket.getDataRaw())
                rawSocket.sendto(packet, (host, 1))
                icmpPacket.sendEchoRequest()
                t = time.time()
                started = time.time()
                ready = select.select([rawSocket], [], [], limit)
                # print(ready)
                timeInSelect = (time.time() - started)

                if ready[0] == []:
                    print("ready - the request timed out")

                recv, addr = rawSocket.recvfrom(1024)
                print(addr)
                timeRecv = time.time()
                limit = limit - timeInSelect

                if limit <= 0:
                    print("limit - the request timed out")

            except timeout:
                continue

            else:
                header = recv[20:28]
                req_type, code, checksum, packId, sequence = struct.unpack("BBHHH", header)

                if req_type == 11:
                    numBytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recv[28:28 + numBytes])[0]
                    print(" %d   rtt=%.0f ms %s" % (hop, (timeRecv - t) * 1000, addr[0]))
                elif req_type == 3:
                    numBytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recv[28:28 + numBytes])[0]
                    print(" %d   rtt=%0.f ms %s" % (hop, (timeRecv - t) * 1000, addr[0]))
                elif req_type == 0:
                    numBytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recv[28:28 + numBytes])[0]
                    print(" %d   rtt=%0.f ms %s" % (hop, (timeRecv - timeSent) * 1000, addr[0]))
                    return
                else:
                    print("unexpected error")
                    break
            finally:
                rawSocket.close()