rule TTP_XOR_QUAD_CurrentVersionRun_2770 {
  strings:
    $key_2770 = { 74 1f [2] 50 11 [2] 7b 3d [2] 55 1f [2] 41 04 [2] 4e 1e [2] 50 03 [2] 52 02 [2] 49 04 [2] 55 03 [2] 49 2c }

  condition:
    any of them
}