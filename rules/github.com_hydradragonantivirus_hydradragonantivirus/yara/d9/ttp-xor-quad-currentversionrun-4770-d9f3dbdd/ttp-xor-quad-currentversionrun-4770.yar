rule TTP_XOR_QUAD_CurrentVersionRun_4770 {
  strings:
    $key_4770 = { 14 1f [2] 30 11 [2] 1b 3d [2] 35 1f [2] 21 04 [2] 2e 1e [2] 30 03 [2] 32 02 [2] 29 04 [2] 35 03 [2] 29 2c }

  condition:
    any of them
}