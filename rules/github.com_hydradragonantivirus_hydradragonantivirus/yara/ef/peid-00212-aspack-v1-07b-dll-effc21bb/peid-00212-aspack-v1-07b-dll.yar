rule PEiD_00212_ASPack_v1_07b__DLL__ {
  meta:
    description = "[ASPack v1.07b (DLL)]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 00 00 00 00 5D ?? ?? ?? ?? ?? ?? B8 ?? ?? ?? ?? 03 C5 }

  condition:
    $a
}