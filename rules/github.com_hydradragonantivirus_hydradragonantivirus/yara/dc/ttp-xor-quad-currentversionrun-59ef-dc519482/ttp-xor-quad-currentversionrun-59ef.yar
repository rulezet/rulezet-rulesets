rule TTP_XOR_QUAD_CurrentVersionRun_59ef {
  strings:
    $key_59ef = { 0a 80 [2] 2e 8e [2] 05 a2 [2] 2b 80 [2] 3f 9b [2] 30 81 [2] 2e 9c [2] 2c 9d [2] 37 9b [2] 2b 9c [2] 37 b3 }

  condition:
    any of them
}