rule TTP_XOR_QUAD_CurrentVersionRun_7670 {
  strings:
    $key_7670 = { 25 1f [2] 01 11 [2] 2a 3d [2] 04 1f [2] 10 04 [2] 1f 1e [2] 01 03 [2] 03 02 [2] 18 04 [2] 04 03 [2] 18 2c }

  condition:
    any of them
}