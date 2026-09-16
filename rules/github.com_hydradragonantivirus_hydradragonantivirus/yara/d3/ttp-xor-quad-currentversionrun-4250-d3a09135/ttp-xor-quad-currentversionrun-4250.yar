rule TTP_XOR_QUAD_CurrentVersionRun_4250 {
  strings:
    $key_4250 = { 11 3f [2] 35 31 [2] 1e 1d [2] 30 3f [2] 24 24 [2] 2b 3e [2] 35 23 [2] 37 22 [2] 2c 24 [2] 30 23 [2] 2c 0c }

  condition:
    any of them
}