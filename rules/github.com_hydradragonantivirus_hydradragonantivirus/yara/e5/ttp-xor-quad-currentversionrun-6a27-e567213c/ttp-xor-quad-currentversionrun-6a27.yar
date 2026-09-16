rule TTP_XOR_QUAD_CurrentVersionRun_6a27 {
  strings:
    $key_6a27 = { 39 48 [2] 1d 46 [2] 36 6a [2] 18 48 [2] 0c 53 [2] 03 49 [2] 1d 54 [2] 1f 55 [2] 04 53 [2] 18 54 [2] 04 7b }

  condition:
    any of them
}