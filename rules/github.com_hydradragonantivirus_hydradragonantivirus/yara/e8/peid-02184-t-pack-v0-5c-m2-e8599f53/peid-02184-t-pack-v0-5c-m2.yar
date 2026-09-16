rule PEiD_02184_T_PACK_v0_5c__m2_ {
  meta:
    description = "[T-PACK v0.5c -m2]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? FD 60 BE ?? ?? BF ?? ?? B9 ?? ?? F3 A4 8B F7 BF ?? ?? FC 46 E9 CE FD }

  condition:
    $a
}