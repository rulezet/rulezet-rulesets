rule TTP_XOR_QUAD_CurrentVersionRun_3a17 {
  strings:
    $key_3a17 = { 69 78 [2] 4d 76 [2] 66 5a [2] 48 78 [2] 5c 63 [2] 53 79 [2] 4d 64 [2] 4f 65 [2] 54 63 [2] 48 64 [2] 54 4b }

  condition:
    any of them
}