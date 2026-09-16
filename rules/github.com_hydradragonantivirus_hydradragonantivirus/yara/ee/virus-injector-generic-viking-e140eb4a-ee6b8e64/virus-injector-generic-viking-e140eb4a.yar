rule Virus_Injector_Generic_Viking_E140EB4A {
  meta:
    description = "datamaliciousorder - file Virus.Injector_Generic.Viking.E140EB4A.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4815db2ff7ef39d0547045bcf6b0c3b7bd27e52b73c65bb01830f0e31467033d"

  strings:
    $s1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><dependency><dependentAssembly><assemblyIdentity ty" ascii
    $s2 = "@Adobe End User License Agreemen" fullword wide
    $s3 = "(c) Adobe Systems Incorporated.  All rights reserved." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}