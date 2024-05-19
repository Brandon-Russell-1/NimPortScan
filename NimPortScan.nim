import os, net, strformat, strutils, posix, threadpool

# Function to set the timeout for a socket
proc setSocketTimeout(socket: Socket, timeout: int) =
  var tv: Timeval
  tv.tv_sec = Time(timeout div 1000)        # Convert to Time (which is distinct clong)
  tv.tv_usec = Suseconds((timeout mod 1000) * 1000)  # Convert to Suseconds (which is int)
  let socklen = SockLen(sizeof(tv))
  if setsockopt(socket.getFd(), SOL_SOCKET, SO_RCVTIMEO, cast[pointer](addr tv), socklen) != 0:
    raise newException(OSError, "Failed to set socket receive timeout")
  if setsockopt(socket.getFd(), SOL_SOCKET, SO_SNDTIMEO, cast[pointer](addr tv), socklen) != 0:
    raise newException(OSError, "Failed to set socket send timeout")

# Function to scan a single TCP port with a timeout
proc scanTcpPort(host: string, port: int, timeout: int): bool =
  var socket: Socket
  try:
    socket = newSocket()
    setSocketTimeout(socket, timeout)
    socket.connect(host, Port(port))
    return true
  except OSError:
    return false
  finally:
    socket.close()

# Function to scan a single UDP port with a timeout
proc scanUdpPort(host: string, port: int, timeout: int): bool =
  var socket: Socket
  try:
    socket = newSocket(posix.AF_INET, posix.SOCK_DGRAM, posix.IPPROTO_UDP)
    setSocketTimeout(socket, timeout)
    socket.sendTo(host, Port(port), "test")
    var buffer: array[256, char]
    discard socket.recv(addr buffer, buffer.len)
    return true
  except OSError:
    return false
  finally:
    socket.close()

# Task function to scan a port and print the result
proc scanPortTask(host: string, port: int, timeout: int, showClosedPorts: bool, protocol: string) {.thread.} =
  let openPort = if protocol == "tcp": scanTcpPort(host, port, timeout) else: scanUdpPort(host, port, timeout)
  if openPort:
    echo &"Port {port} ({protocol.toUpperAscii()}) is open"
  elif showClosedPorts:
    echo &"Port {port} ({protocol.toUpperAscii()}) is closed"

# Function to scan a range of ports using multithreading
proc scanPorts(host: string, startPort, endPort, timeout: int, showClosedPorts: bool, maxThreads: int, protocol: string) =
  echo &"Scanning {host} from port {startPort} to port {endPort} using {protocol.toUpperAscii()} with a max of {maxThreads} threads"
  var threadCount = 0
  for port in startPort..endPort:
    if threadCount >= maxThreads:
      threadpool.sync()  # Wait for some tasks to complete before spawning more
      threadCount = 0
    spawn scanPortTask(host, port, timeout, showClosedPorts, protocol)
    threadCount += 1
  threadpool.sync()  # Wait for all tasks to complete

# Function to parse command-line arguments
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

# Main function
proc main() =
  let (host, startPort, endPort, timeout, showClosedPorts, maxThreads, protocol) = parseArgs()
  scanPorts(host, startPort, endPort, timeout, showClosedPorts, maxThreads, protocol)

# Run the main function
when isMainModule:
  main()
