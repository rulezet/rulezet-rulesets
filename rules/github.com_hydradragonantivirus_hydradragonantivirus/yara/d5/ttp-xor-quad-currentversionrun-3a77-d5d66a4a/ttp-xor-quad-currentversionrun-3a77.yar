rule TTP_XOR_QUAD_CurrentVersionRun_3a77 {
  strings:
    $key_3a77 = { 69 18 [2] 4d 16 [2] 66 3a [2] 48 18 [2] 5c 03 [2] 53 19 [2] 4d 04 [2] 4f 05 [2] 54 03 [2] 48 04 [2] 54 2b }

  condition:
    any of them
}