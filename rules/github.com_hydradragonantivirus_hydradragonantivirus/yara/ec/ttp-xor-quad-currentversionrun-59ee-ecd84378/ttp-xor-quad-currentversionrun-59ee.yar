rule TTP_XOR_QUAD_CurrentVersionRun_59ee {
  strings:
    $key_59ee = { 0a 81 [2] 2e 8f [2] 05 a3 [2] 2b 81 [2] 3f 9a [2] 30 80 [2] 2e 9d [2] 2c 9c [2] 37 9a [2] 2b 9d [2] 37 b2 }

  condition:
    any of them
}