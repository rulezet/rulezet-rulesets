rule PEiD_00255_ASProtect_v1_0_ {
  meta:
    description = "[ASProtect v1.0]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 01 ?? ?? ?? 90 5D 81 ED ?? ?? ?? ?? BB ?? ?? ?? ?? 03 DD 2B 9D }

  condition:
    $a
}