rule PEiD_02450_Upx_v1_2____Marcus___Lazlo_ {
  meta:
    description = "[Upx v1.2 -> Marcus & Lazlo]"
    ep_only     = "true"

  strings:
    $a = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF EB 05 A4 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 F2 31 C0 40 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 75 07 8B 1E 83 EE FC 11 DB 73 E6 31 C9 83 }

  condition:
    $a
}