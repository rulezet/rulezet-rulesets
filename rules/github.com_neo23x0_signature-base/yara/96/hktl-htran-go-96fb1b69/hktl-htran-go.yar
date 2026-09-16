rule HKTL_htran_go {
   meta:
      author = "Jeff Beley"
      hash1 = "4acbefb9f7907c52438ebb3070888ddc8cddfe9e3849c9d0196173a422b9035f"
      description = "Detects go based htran variant"
      date = "2019-01-09"
      id = "bd9409e3-3d4c-57d6-af60-b6d6bd93d46b"
   strings:
      $s1 = "https://github.com/cw1997/NATBypass" fullword ascii
      $s2 = "-slave ip1:port1 ip2:port2" fullword ascii
      $s3 = "-tran port1 ip:port2" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and 1 of them
}