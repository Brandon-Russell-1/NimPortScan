import os, net, strformat, strutils, posix, threadpool, times

proc setSocketTimeout(socket: Socket, timeout: int) =
  var tv: posix.Timeval
  tv.tv_sec = posix.Time(timeout div 1000)
  tv.tv_usec = posix.Suseconds((timeout mod 1000) * 1000)
  let socklen = posix.SockLen(sizeof(tv))
  if setsockopt(socket.getFd(), SOL_SOCKET, SO_RCVTIMEO, cast[pointer](addr tv), socklen) != 0:
    raise newException(OSError, "Failed to set socket receive timeout")
  if setsockopt(socket.getFd(), SOL_SOCKET, SO_SNDTIMEO, cast[pointer](addr tv), socklen) != 0:
    raise newException(OSError, "Failed to set socket send timeout")

proc scanTcpPort(host: string, port: int, timeout: int): string =
  var socket: Socket
  try:
    socket = newSocket()
    if socket.getFd() == InvalidSocket:
      raise newException(OSError, "Failed to create TCP socket")
    setSocketTimeout(socket, timeout)
    socket.connect(host, Port(port))
    return "open"
  except OSError as e:
    echo "OSError during TCP scan: ", e.msg
    return "closed"
  finally:
    socket.close()

proc listenForICMP(icmpSocket: SocketHandle, timeout: int): string =
  var buffer: array[256, char]
  let startTime = epochTime()
  while epochTime() - startTime < (float(timeout) / 1000.0):
    try:
      let bytesRead = posix.recv(icmpSocket, addr buffer, buffer.len, 0)
      if bytesRead == -1:
        let err = osLastError()
        if err.int == EAGAIN or err.int == EWOULDBLOCK:
          continue
        else:
          echo "ICMP recv error: ", strerror(cint(err))
        return "open|filtered"
      elif bytesRead > 0:
        echo "Received packet of length: ", bytesRead
        if bytesRead >= 28:
          let ipHeaderLen = (buffer[0].ord and 0x0F) * 4
          if ipHeaderLen + 8 <= bytesRead:
            let icmpType = buffer[ipHeaderLen].ord
            let icmpCode = buffer[ipHeaderLen + 1].ord
            echo "ICMP type: ", icmpType, ", ICMP code: ", icmpCode
            if icmpType == 3:
              case icmpCode
              of 1, 2, 9, 10, 13:
                return "filtered"
              of 3:
                return "closed"
              else:
                return "open|filtered"
            else:
              return "open"  # Any other ICMP type is considered open
    except OSError as e:
      echo "OSError during recv: ", e.msg
      discard
  return "open|filtered"

proc scanUdpPort(host: string, port: int, timeout: int, icmpSocket: SocketHandle): string =
  var udpSocket: Socket
  try:
    udpSocket = newSocket(posix.AF_INET, posix.SOCK_DGRAM, posix.IPPROTO_UDP)
    if udpSocket.getFd() == InvalidSocket:
      raise newException(OSError, "Failed to create UDP socket")
    setSocketTimeout(udpSocket, timeout)
    udpSocket.sendTo(host, Port(port), "test")
    return listenForICMP(icmpSocket, timeout)
  except OSError as e:
    echo "OSError during UDP scan: ", e.msg
    return "open|filtered"
  finally:
    udpSocket.close()

proc scanPortTask(host: string, port: int, timeout: int, showClosedPorts: bool, protocol: string, icmpSocket: SocketHandle) {.thread.} =
  let state = if protocol == "tcp": scanTcpPort(host, port, timeout) else: scanUdpPort(host, port, timeout, icmpSocket)
  if state == "open" or state == "filtered" or state == "open|filtered":
    echo &"Port {port} ({protocol.toUpperAscii()}) is {state}"
  elif showClosedPorts:
    echo &"Port {port} ({protocol.toUpperAscii()}) is {state}"

proc scanPorts(host: string, startPort, endPort, timeout: int, showClosedPorts: bool, maxThreads: int, protocol: string) =
  echo &"Scanning {host} from port {startPort} to port {endPort} using {protocol.toUpperAscii()} with a max of {maxThreads} threads"
  var threadCount = 0
  var icmpSocket: SocketHandle
  if protocol == "udp":
    try:
      echo "Creating ICMP socket for UDP scanning"
      icmpSocket = socket(posix.AF_INET, posix.SOCK_RAW, posix.IPPROTO_ICMP)
      let fd = int(icmpSocket)
      echo "ICMP socket created with fd: ", fd
      if icmpSocket == InvalidSocket:
        raise newException(OSError, "Failed to create ICMP socket")
      let icmpSocketWrapper = newSocket(icmpSocket)
      setSocketTimeout(icmpSocketWrapper, timeout)
    except OSError as e:
      echo "Error creating ICMP socket: ", e.msg
      quit(1)
    except RangeDefect as e:
      echo "RangeDefect while creating ICMP socket: ", e.msg
      quit(1)
    except CatchableError as e:
      echo "CatchableError while creating ICMP socket: ", e.msg
      quit(1)
    except Exception as e:
      echo "Unhandled exception while creating ICMP socket: ", e.msg
      quit(1)
  for port in startPort..endPort:
    echo &"Spawning task for port {port}"
    if threadCount >= maxThreads:
      threadpool.sync()
      threadCount = 0
    spawn scanPortTask(host, port, timeout, showClosedPorts, protocol, icmpSocket)
    threadCount += 1
  threadpool.sync()
  if protocol == "udp":
    discard close(icmpSocket)

proc parseArgs(): (string, int, int, int, bool, int, string) =
  if paramCount() < 6 or paramCount() > 7:
    echo "Usage: port_scanner <IP address> <start port> <end port> <timeout> <maxThreads> <protocol> [showClosedPorts]"
    quit(1)
  
  let ip = paramStr(1)
  let startPort = parseInt(paramStr(2))
  let endPort = parseInt(paramStr(3))
  let timeout = parseInt(paramStr(4))
  let maxThreads = parseInt(paramStr(5))
  let protocol = paramStr(6).toLower()
  let showClosedPorts = if paramCount() == 7: parseBool(paramStr(7)) else: false
  
  if not (0 < startPort and startPort <= 65535 and 0 < endPort and endPort <= 65535 and startPort <= endPort and timeout > 0 and maxThreads > 0 and (protocol == "tcp" or protocol == "udp")):
    echo "Invalid input. Ports must be between 1 and 65535, start port must be less than or equal to end port, timeout must be a positive integer, maxThreads must be a positive integer, and protocol must be either 'tcp' or 'udp'."
    quit(1)
  
  return (ip, startPort, endPort, timeout, showClosedPorts, maxThreads, protocol)

proc main() =
  let (host, startPort, endPort, timeout, showClosedPorts, maxThreads, protocol) = parseArgs()
  scanPorts(host, startPort, endPort, timeout, showClosedPorts, maxThreads, protocol)

when isMainModule:
  main()
