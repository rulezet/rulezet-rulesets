rule Virus_Hijack_Gen_Trojan_ShellObject_uGZ_ayM4QWg_38_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.uGZ@ayM4QWg_38_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c98a9e7e704fa4214901cb2a1403121b07965e74db4249b21423c66e91b48a57"

  strings:
    $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/" ascii
    $s2 = "06:39        \"> <rdf:RDF xmlns:rdf=\"http://www.w3.org/199l/02/22-rdf-syntax-ns#\"> <rdf:Description rdf:about=\"\" xmlns:xmp=" ascii
    $s3 = "v,Reference Viewing Condition in IEC61966-" fullword ascii
    $s4 = "Adobe Photoshop-CC 2018 (Windows)" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}