rule TTP_XOR_QUAD_CurrentVersionRun_59f8 {
  strings:
    $key_59f8 = { 0a 97 [2] 2e 99 [2] 05 b5 [2] 2b 97 [2] 3f 8c [2] 30 96 [2] 2e 8b [2] 2c 8a [2] 37 8c [2] 2b 8b [2] 37 a4 }

  condition:
    any of them
}