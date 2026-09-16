rule TTP_XOR_QUAD_CurrentVersionRun_420d {
  strings:
    $key_420d = { 11 62 [2] 35 6c [2] 1e 40 [2] 30 62 [2] 24 79 [2] 2b 63 [2] 35 7e [2] 37 7f [2] 2c 79 [2] 30 7e [2] 2c 51 }

  condition:
    any of them
}