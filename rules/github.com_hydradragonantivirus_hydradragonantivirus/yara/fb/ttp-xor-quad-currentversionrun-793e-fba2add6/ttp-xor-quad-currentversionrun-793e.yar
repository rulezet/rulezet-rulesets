rule TTP_XOR_QUAD_CurrentVersionRun_793e {
  strings:
    $key_793e = { 2a 51 [2] 0e 5f [2] 25 73 [2] 0b 51 [2] 1f 4a [2] 10 50 [2] 0e 4d [2] 0c 4c [2] 17 4a [2] 0b 4d [2] 17 62 }

  condition:
    any of them
}