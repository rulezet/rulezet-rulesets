rule TTP_XOR_QUAD_CurrentVersionRun_3d6b {
  strings:
    $key_3d6b = { 6e 04 [2] 4a 0a [2] 61 26 [2] 4f 04 [2] 5b 1f [2] 54 05 [2] 4a 18 [2] 48 19 [2] 53 1f [2] 4f 18 [2] 53 37 }

  condition:
    any of them
}