rule WinPayloads_Payload_RID2EA5 : DEMO EXE FILE HKTL {
   meta:
      description = "Detects WinPayloads Payload"
      author = "Florian Roth"
      reference = "https://github.com/nccgroup/Winpayloads"
      date = "2017-07-11 11:23:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "23a24f99c3c6c00cd4bf6cb968f813ba2ceadfa846c7f169f412bcbb71ba6573"
      hash2 = "35069905d9b7ba1fd57c8df03614f563504194e4684f47aafa08ebb8d9409d0b"
      hash3 = "a28d107f168d85c38fc76229b14561b472e60e60973eb10b6b554c1f57469322"
      tags = "DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "bpayload.exe.manifest" fullword ascii
      $s2 = "spayload" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 10000KB and all of them )
}