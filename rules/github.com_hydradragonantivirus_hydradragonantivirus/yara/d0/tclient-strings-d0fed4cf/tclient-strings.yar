rule tclient_strings {
  meta:
    author = "Etienne Maynier"
    email  = "etienne@citizenlab.ca"

  strings:
    $a = "sdf81msdf7"
    $b = "software\\klive"
    $c = "\\Registry\\User\\%s\\Software\\KLive"
    $d = "%s\\wab32res.dll"
    $e = "[!]NtDeleteValueKey Error:%ul"
    $f = "%sDebugLog.TXT"
    $g = "Server connect to [%s:%d] Sucesse! token = %s"
    $h = "192.168.70.1"
    $i = "Start %d connect %s:%d"

  condition:
    uint16(0) == 0x5A4D and 3 of them
}