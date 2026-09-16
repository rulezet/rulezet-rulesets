rule TTP_XOR_QUAD_CurrentVersionRun_6e15 {
  strings:
    $key_6e15 = { 3d 7a [2] 19 74 [2] 32 58 [2] 1c 7a [2] 08 61 [2] 07 7b [2] 19 66 [2] 1b 67 [2] 00 61 [2] 1c 66 [2] 00 49 }

  condition:
    any of them
}