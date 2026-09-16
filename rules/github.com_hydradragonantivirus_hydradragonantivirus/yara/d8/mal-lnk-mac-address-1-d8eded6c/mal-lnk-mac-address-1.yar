rule MAL_LNK_MAC_ADDRESS_1 {
  meta:
    author      = "@qutluch@infosec.exchange"
    description = "Rule matching on LNK files based on the host MAC address."
    reference   = "https://blog.nviso.eu/2017/04/04/tracking-threat-actors-through-lnk-files/"
    DaysofYARA  = "5/100"
    license     = "BSD-2-Clause"
    date        = "2024-01-05"
    version     = "1.0"

  strings:
    $tracker_data1 = "\x00PV\xae\x90\x0e"
    $tracker_data2 = "\x00PV\xae\x90\x0e"

  condition:
    uint32(0) == 0x4c << 24 and (
      $tracker_data1 at (filesize - 24)
      or $tracker_data2 at (filesize - 24)
    )
}