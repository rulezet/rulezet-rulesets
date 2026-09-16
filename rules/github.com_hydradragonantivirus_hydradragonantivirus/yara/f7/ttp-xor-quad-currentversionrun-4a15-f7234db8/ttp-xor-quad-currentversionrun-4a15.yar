rule TTP_XOR_QUAD_CurrentVersionRun_4a15 {
  strings:
    $key_4a15 = { 19 7a [2] 3d 74 [2] 16 58 [2] 38 7a [2] 2c 61 [2] 23 7b [2] 3d 66 [2] 3f 67 [2] 24 61 [2] 38 66 [2] 24 49 }

  condition:
    any of them
}