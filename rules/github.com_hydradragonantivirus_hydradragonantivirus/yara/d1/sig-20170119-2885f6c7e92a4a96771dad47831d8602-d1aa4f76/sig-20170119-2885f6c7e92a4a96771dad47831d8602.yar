rule sig_20170119_2885f6c7e92a4a96771dad47831d8602 {
  meta:
    description = "datamaliciousorder - file 20170119_2885f6c7e92a4a96771dad47831d8602.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dc193f029b8fd348e9512995833589bc5d92f8abf300f8d4c58d7ffcb70204a5"

  strings:
    $s1 = "var zdojudum = new Function(tfipgoccirusulkosididxedtozdigywuqicygparmeknuhehijnoljateqagawqazqiwofxemxeghypaplyjtimivylnavostuc" ascii
    $s2 = "] + azercihakgycaqhemluxogqewazpesyxwuwifrecxonpetixemogifkohylqaryqmerbexqudaqxymbewowuvlisetnudmanulrusbirlidemnomje[0] + nako" ascii
    $s3 = "var zdojudum = new Function(tfipgoccirusulkosididxedtozdigywuqicygparmeknuhehijnoljateqagawqazqiwofxemxeghypaplyjtimivylnavostuc" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}