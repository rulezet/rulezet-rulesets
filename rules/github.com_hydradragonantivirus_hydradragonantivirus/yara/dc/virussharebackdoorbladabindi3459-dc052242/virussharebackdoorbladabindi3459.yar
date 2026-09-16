rule VirusShareBackDoorBladabindi3459 {
  meta:
    description = "datamaliciousorder - file VirusShareBackDoorBladabindi3459.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f3708be0f01799bf40ab729a335e3b689049b6017f2671fbf92bf2579de24595"

  strings:
    $s1 = "yleKZlCXnrEgcQD3gk.HIqNmi47ta6wQLwpfy/nTiUWRPw4mCFqxfA7R/dbYnXxZRxVvAxO5NqK`1[[System.Object, mscorlib, Version=2.0.0.0, Culture" ascii
    $s2 = "<Module>{1CEED371-6F61-49B9-9254-30B60E8750F3}" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}