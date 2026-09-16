rule TTP_XOR_QUAD_CurrentVersionRun_0c01 {
  strings:
    $key_0c01 = { 5f 6e [2] 7b 60 [2] 50 4c [2] 7e 6e [2] 6a 75 [2] 65 6f [2] 7b 72 [2] 79 73 [2] 62 75 [2] 7e 72 [2] 62 5d }

  condition:
    any of them
}