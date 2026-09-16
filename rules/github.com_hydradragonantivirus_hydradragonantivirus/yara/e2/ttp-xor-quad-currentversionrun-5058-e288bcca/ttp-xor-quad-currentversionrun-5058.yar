rule TTP_XOR_QUAD_CurrentVersionRun_5058 {
  strings:
    $key_5058 = { 03 37 [2] 27 39 [2] 0c 15 [2] 22 37 [2] 36 2c [2] 39 36 [2] 27 2b [2] 25 2a [2] 3e 2c [2] 22 2b [2] 3e 04 }

  condition:
    any of them
}