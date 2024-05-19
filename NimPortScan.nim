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

# Function to scan a single port with a timeout
proc scanPort(host: string, port: int, timeout: int): bool =
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

# Task function to scan a port and print the result
proc scanPortTask(host: string, port: int, timeout: int, showClosedPorts: bool) {.thread.} =
  if scanPort(host, port, timeout):
    echo &"Port {port} is open"
  elif showClosedPorts:
    echo &"Port {port} is closed"

# Function to scan a range of ports using multithreading
proc scanPorts(host: string, startPort, endPort, timeout: int, showClosedPorts: bool, maxThreads: int) =
  echo &"Scanning {host} from port {startPort} to port {endPort} with a max of {maxThreads} threads"
  var threadCount = 0
  for port in startPort..endPort:
    if threadCount >= maxThreads:
      threadpool.sync()  # Wait for some tasks to complete before spawning more
      threadCount = 0
    spawn scanPortTask(host, port, timeout, showClosedPorts)
    threadCount += 1
  threadpool.sync()  # Wait for all tasks to complete

# Function to parse command-line arguments
proc parseArgs(): (string, int, int, int, bool, int) =
  if paramCount() < 5 or paramCount() > 6:
    echo "Usage: port_scanner <IP address> <start port> <end port> <timeout> <maxThreads> [showClosedPorts]"
    quit(1)
  
  let ip = paramStr(1)
  let startPort = parseInt(paramStr(2))
  let endPort = parseInt(paramStr(3))
  let timeout = parseInt(paramStr(4))
  let maxThreads = parseInt(paramStr(5))
  let showClosedPorts = if paramCount() == 6: parseBool(paramStr(6)) else: false
  
  if not (0 < startPort and startPort <= 65535 and 0 < endPort and endPort <= 65535 and startPort <= endPort and timeout > 0 and maxThreads > 0):
    echo "Invalid input. Ports must be between 1 and 65535, start port must be less than or equal to end port, timeout must be a positive integer, and maxThreads must be a positive integer."
    quit(1)
  
  return (ip, startPort, endPort, timeout, showClosedPorts, maxThreads)

# Main function
proc main() =
  let (host, startPort, endPort, timeout, showClosedPorts, maxThreads) = parseArgs()
  scanPorts(host, startPort, endPort, timeout, showClosedPorts, maxThreads)

# Run the main function
when isMainModule:
  main()
