rule TTP_XOR_QUAD_CurrentVersionRun_0158 {
  strings:
    $key_0158 = { 52 37 [2] 76 39 [2] 5d 15 [2] 73 37 [2] 67 2c [2] 68 36 [2] 76 2b [2] 74 2a [2] 6f 2c [2] 73 2b [2] 6f 04 }

  condition:
    any of them
}