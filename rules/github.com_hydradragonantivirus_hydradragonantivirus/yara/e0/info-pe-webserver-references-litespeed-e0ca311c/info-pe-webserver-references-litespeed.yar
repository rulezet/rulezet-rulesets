rule INFO_PE_WebServer_References_LiteSpeed {
  meta:
    author      = "Greg Lesnewich"
    date        = "2024-01-17"
    version     = "1.0"
    description = "track executable files that reference the LiteSpeed web server, which might be a fake response page to being probed "
    DaysofYARA  = "17/100"

  strings:
    $ = "LiteSpeed" nocase ascii wide

  condition:
    uint16be(0) == 0x4d5a and all of them
}