rule PEiD_02104_SkD_Undetectabler_Pro_2_0__No_UPX_Method_____SkD_ {
  meta:
    description = "[SkD Undetectabler Pro 2.0 (No UPX Method) -> SkD]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 83 C4 F0 B8 FC 26 00 10 E8 EC F3 FF FF 6A 0F E8 15 F5 FF FF E8 64 FD FF FF E8 BB ED FF FF 8D 40 }

  condition:
    $a
}