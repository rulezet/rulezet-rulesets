rule CN_Honker__lcx_HTran2_4_htran20_RID324C : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - from files lcx.exe, HTran2.4.exe, htran20.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:59:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "524f986692f55620013ab5a06bf942382e64d38a"
      hash2 = "b992bf5b04d362ed3757e90e57bc5d6b2a04e65c"
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "[SERVER]connection to %s:%d error" fullword ascii
      $s2 = "[+] OK! I Closed The Two Socket." fullword ascii
      $s3 = "[+] Start Transmit (%s:%d <-> %s:%d) ......" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 440KB and all of them
}