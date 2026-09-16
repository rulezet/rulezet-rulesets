rule TTP_XOR_QUAD_CurrentVersionRun_3d39 {
  strings:
    $key_3d39 = { 6e 56 [2] 4a 58 [2] 61 74 [2] 4f 56 [2] 5b 4d [2] 54 57 [2] 4a 4a [2] 48 4b [2] 53 4d [2] 4f 4a [2] 53 65 }

  condition:
    any of them
}