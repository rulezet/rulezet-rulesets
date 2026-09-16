rule PEiD_00861_Go32Stub_v_2_00T_DOS_Extender_ {
  meta:
    description = "[Go32Stub v.2.00T DOS-Extender]"
    ep_only     = "true"

  strings:
    $a = { 0E 1F 8C 1E ?? ?? 8C 06 ?? ?? FC B4 30 CD 21 3C }

  condition:
    $a
}