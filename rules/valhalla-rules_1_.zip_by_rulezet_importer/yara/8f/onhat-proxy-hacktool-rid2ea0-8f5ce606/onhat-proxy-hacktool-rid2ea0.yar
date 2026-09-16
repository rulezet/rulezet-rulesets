rule ONHAT_Proxy_Hacktool_RID2EA0 : CHINA DEMO EXE FILE HKTL T1020 T1090 {
   meta:
      description = "Detects ONHAT Proxy - Htran like SOCKS hack tool used by Chinese APT groups"
      author = "Florian Roth"
      reference = "https://www.secureworks.com/research/analysis-of-dhs-nccic-indicators"
      date = "2016-05-12 11:22:31"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2025-03-14"
      hash1 = "30b2de0a802a65b4db3a14593126301e6949c1249e68056158b2cc74798bac97"
      hash2 = "94bda24559713c7b8be91368c5016fc7679121fea5d565d3d11b2bb5d5529340"
      hash3 = "a26e75fec3b9f7d5a1c3d0ce1e89e4b0befb7a601da0c69a4cf96301921771dd"
      tags = "CHINA, DEMO, EXE, FILE, HKTL, T1020, T1090"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "INVALID PARAMETERS. TYPE ONHAT.EXE -h FOR HELP INFORMATION." fullword ascii
      $s2 = "[ONHAT] LISTENS (S, %d.%d.%d.%d, %d) ERROR." fullword ascii
      $s3 = "[ONHAT] CONNECTS (T, %d.%d.%d.%d, %d.%d.%d.%d, %d) ERROR." fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 80KB and ( 1 of ( $s* ) ) ) or ( 2 of them )
}