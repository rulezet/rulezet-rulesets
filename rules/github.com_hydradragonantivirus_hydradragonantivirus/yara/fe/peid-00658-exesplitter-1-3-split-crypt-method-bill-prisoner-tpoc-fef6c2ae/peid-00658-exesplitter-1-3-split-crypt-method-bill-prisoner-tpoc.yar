rule PEiD_00658_ExeSplitter_1_3__Split_Crypt_Method_____Bill_Prisoner___TPOC_ {
  meta:
    description = "[ExeSplitter 1.3 (Split+Crypt Method) -> Bill Prisoner / TPOC]"
    ep_only     = "true"

  strings:
    $a = { E8 00 00 00 00 5D 81 ED 05 10 40 00 B9 ?? ?? ?? ?? 8D 85 1D 10 40 00 80 30 66 40 E2 FA 8F 98 67 66 66 ?? ?? ?? ?? ?? ?? ?? 66 }

  condition:
    $a
}