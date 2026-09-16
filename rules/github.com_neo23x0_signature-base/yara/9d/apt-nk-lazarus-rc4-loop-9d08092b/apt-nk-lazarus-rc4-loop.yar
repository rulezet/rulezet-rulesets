rule APT_NK_Lazarus_RC4_Loop {
   meta: 
      author = "f-secure "
      description = "Detects RC4 loop in Lazarus Group implant" 
      date = "2020-06-10"
      reference = "https://labs.f-secure.com/publications/ti-report-lazarus-group-cryptocurrency-vertical"
      id = "a9503795-b4b8-505e-a1bf-df64ec8c1c32"
   strings:
      $str_rc4_loop = { 41 FE 8? 00 01 00 00 45 0F B6 ?? 00 01 00 00 48 
                        FF C? 43 0F B6 0? ?? 41 00 8? 01 01 00 00 41 0F 
                        B6 ?? 01 01 00 00 }
   condition:
      int16(0) == 0x5a4d and filesize < 3000KB and $str_rc4_loop
}