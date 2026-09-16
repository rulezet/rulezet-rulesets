rule Virus_Hijack_Backdoor_Hangup_B_275_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_275_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "02cad63fa49e65068d0d9d8eaca492418804344314d5a75dd1ffd4e27f492fb4"

  strings:
    $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity type=\"win32\" name=\"FireFox\" v" ascii
    $s2 = "1.0.0.0\" processorArchitecture=\"*\"></assemblyIdentity><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"" ascii
    $s3 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity type=\"win32\" name=\"FireFox\" v" ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and all of them
}