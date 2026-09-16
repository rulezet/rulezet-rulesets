rule TTP_XOR_QUAD_CurrentVersionRun_59f3 {
  strings:
    $key_59f3 = { 0a 9c [2] 2e 92 [2] 05 be [2] 2b 9c [2] 3f 87 [2] 30 9d [2] 2e 80 [2] 2c 81 [2] 37 87 [2] 2b 80 [2] 37 af }

  condition:
    any of them
}