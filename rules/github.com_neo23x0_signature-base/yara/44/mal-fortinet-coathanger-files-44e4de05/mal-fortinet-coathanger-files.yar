rule MAL_Fortinet_COATHANGER_Files {
   meta:
      description = "Detects COATHANGER files by used filenames"
      malware = "COATHANGER"
      author = "NLD MIVD - JSCU"
      date = "2024-02-06"
      reference = "https://www.ncsc.nl/documenten/publicaties/2024/februari/6/mivd-aivd-advisory-coathanger-tlp-clear"
      id = "0aa2f266-247b-5510-9fd9-4c7940fb80e8"
   strings:
      $1 = "/data2/"
      $2 = "/httpsd"
      $3 = "/preload.so"
      $4 = "/authd"
      $5 = "/tmp/packfile"
      $6 = "/smartctl"
      $7 = "/etc/ld.so.preload"
      $8 = "/newcli"
      $9 = "/bin/busybox"
   condition:
      (uint32(0) == 0x464c457f or uint32(4) == 0x464c457f)
      and filesize < 5MB and 4 of them
}