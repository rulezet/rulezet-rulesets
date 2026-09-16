rule TTP_XOR_QUAD_CurrentVersionRun_0942 {
  strings:
    $key_0942 = { 5a 2d [2] 7e 23 [2] 55 0f [2] 7b 2d [2] 6f 36 [2] 60 2c [2] 7e 31 [2] 7c 30 [2] 67 36 [2] 7b 31 [2] 67 1e }

  condition:
    any of them
}