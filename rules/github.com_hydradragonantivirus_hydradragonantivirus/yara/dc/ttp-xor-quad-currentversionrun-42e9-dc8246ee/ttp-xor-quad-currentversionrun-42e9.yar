rule TTP_XOR_QUAD_CurrentVersionRun_42e9 {
  strings:
    $key_42e9 = { 11 86 [2] 35 88 [2] 1e a4 [2] 30 86 [2] 24 9d [2] 2b 87 [2] 35 9a [2] 37 9b [2] 2c 9d [2] 30 9a [2] 2c b5 }

  condition:
    any of them
}