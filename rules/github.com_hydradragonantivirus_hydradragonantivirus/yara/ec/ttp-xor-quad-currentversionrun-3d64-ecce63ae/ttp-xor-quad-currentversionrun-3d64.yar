rule TTP_XOR_QUAD_CurrentVersionRun_3d64 {
  strings:
    $key_3d64 = { 6e 0b [2] 4a 05 [2] 61 29 [2] 4f 0b [2] 5b 10 [2] 54 0a [2] 4a 17 [2] 48 16 [2] 53 10 [2] 4f 17 [2] 53 38 }

  condition:
    any of them
}