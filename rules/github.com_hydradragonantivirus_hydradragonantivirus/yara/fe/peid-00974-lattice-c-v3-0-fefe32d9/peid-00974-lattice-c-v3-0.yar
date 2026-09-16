rule PEiD_00974_Lattice_C_v3_0_ {
  meta:
    description = "[Lattice C v3.0]"
    ep_only     = "true"

  strings:
    $a = { FA B8 ?? ?? 8E D8 B8 ?? ?? 8E }

  condition:
    $a
}