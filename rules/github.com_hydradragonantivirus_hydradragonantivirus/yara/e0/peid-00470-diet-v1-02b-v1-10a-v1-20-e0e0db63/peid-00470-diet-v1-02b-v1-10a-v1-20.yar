rule PEiD_00470_DIET_v1_02b__v1_10a__v1_20_ {
  meta:
    description = "[DIET v1.02b, v1.10a, v1.20]"
    ep_only     = "true"

  strings:
    $a = { BE ?? ?? BF ?? ?? B9 ?? ?? 3B FC 72 ?? B4 4C CD 21 FD F3 A5 FC }

  condition:
    $a
}