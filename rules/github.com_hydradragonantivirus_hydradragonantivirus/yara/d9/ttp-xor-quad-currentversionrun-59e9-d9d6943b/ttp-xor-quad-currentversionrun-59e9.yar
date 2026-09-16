rule TTP_XOR_QUAD_CurrentVersionRun_59e9 {
  strings:
    $key_59e9 = { 0a 86 [2] 2e 88 [2] 05 a4 [2] 2b 86 [2] 3f 9d [2] 30 87 [2] 2e 9a [2] 2c 9b [2] 37 9d [2] 2b 9a [2] 37 b5 }

  condition:
    any of them
}