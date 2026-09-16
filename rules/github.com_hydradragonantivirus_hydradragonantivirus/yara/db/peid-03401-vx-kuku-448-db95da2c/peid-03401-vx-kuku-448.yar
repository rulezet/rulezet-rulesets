rule PEiD_03401_Vx__Kuku_448_ {
  meta:
    description = "[Vx: Kuku.448]"
    ep_only     = "true"

  strings:
    $a = { AE 75 ED E2 F8 89 3E ?? ?? BA ?? ?? 0E 07 BF ?? ?? EB }

  condition:
    $a
}