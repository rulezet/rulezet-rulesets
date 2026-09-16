rule PEiD_01726_PLINK86_1984__1985_ {
  meta:
    description = "[PLINK86 1984, 1985]"
    ep_only     = "true"

  strings:
    $a = { FA 8C C7 8C D6 8B CC BA ?? ?? 8E C2 26 }

  condition:
    $a
}