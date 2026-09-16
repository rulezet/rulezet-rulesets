rule APT_MAL_APT27_Rshell_Jul24_1_RID3025 : APT DEMO FILE G0027 MAL T1070_003 {
   meta:
      description = "Detects RSHELL / SYSUPDATE backdoor used by APT27"
      author = "Florian Roth"
      reference = "https://x.com/bfv_bund/status/1811364839656185985?s=12&t=C0_T_re0wRP_NfKa27Xw9w"
      date = "2024-07-11 12:27:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "0433edfad648e1e29be54101abaded690302dc7e49ad916cfbbddf99b3ade12c"
      hash2 = "10bb89fdf25c88d3c5623e8d68573124c9a42549750014e3675e2ca342aeba4a"
      hash3 = "2603e1f61363451891c97b0c4ce8acfbfb680d3df4282f9d151ecce3a5679616"
      tags = "APT, DEMO, FILE, G0027, MAL, T1070_003"
      minimum_yara = "3.5.0"
      
   strings:
      $a1 = "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%" ascii
      $a2 = "/proc/self/exe" ascii
      $s1 = "HISTFILE" ascii fullword
      $s2 = "/tmp/guid" ascii fullword
      $sop1 = { e8 ?? ?? ?? ?? c7 43 04 00 00 00 00 8b 3b 85 ff 7e 2? e8 ?? ?? 0? 00 85 c0 7e 0? } 
      $sop2 = { c7 43 04 00 00 00 00 8b 3b 85 ff 7e 2? e8 ?? ?? 0? 00 85 c0 7e 0? f7 d8 } 
   condition: 
      ( uint32be ( 0 ) == 0x7f454c46 or ( uint32be ( 0 ) == 0xcafebabe and uint32be ( 4 ) < 0x20 ) or uint32 ( 0 ) == 0xfeedface or uint32 ( 0 ) == 0xfeedfacf ) and filesize < 2MB and all of ( $a* ) and 2 of ( $s* ) or 3 of ( $s* )
}