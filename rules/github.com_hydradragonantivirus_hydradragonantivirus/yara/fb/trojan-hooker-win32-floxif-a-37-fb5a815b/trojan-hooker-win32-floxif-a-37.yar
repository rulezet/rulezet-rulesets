rule Trojan_Hooker_Win32_Floxif_A_37 {
  meta:
    description = "datamaliciousorder - file Trojan.Hooker_Win32.Floxif.A_37.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bca9f3c3872e057e79c2eb42e7afed4960727db40f377ac93d15dd13f6e2735f"

  strings:
    $s1 = "*Unable to get a list of running processes.*Missing separator character after keyword.Invalid element in a DllStruct.*Unknown o" wide
    $s2 = "Invalid file filter given.*Expected a variable in user function call.1\"Do\" statement has no matching \"Until\" statement.2\"Un" wide
    $s3 = "AutoIt supports the __stdcall (WINAPI) and __cdecl calling conventions.  The __stdcall (WINAPI) convention is used by default bu" wide
    $s4 = "AutoIt v3 Script : 3, 3, 0, 0" fullword wide
    $s5 = "Badly formated Enum statement!Badly formated variable or macro.3This keyword cannot be used after a \"Then\" keyword.>\"Select\"" wide
    $s6 = "Unable to parse line.(Missing right bracket ')' in expression.Missing operator in expression.\"Unbalanced brackets in expressio" wide
    $s7 = "String missing closing quote." fullword wide
    $s8 = "PE Network Manager 0.59 Beta 11" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}