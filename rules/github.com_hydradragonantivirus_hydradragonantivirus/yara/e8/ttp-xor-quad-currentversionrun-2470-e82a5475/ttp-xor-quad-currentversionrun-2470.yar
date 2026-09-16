rule TTP_XOR_QUAD_CurrentVersionRun_2470 {
  strings:
    $key_2470 = { 77 1f [2] 53 11 [2] 78 3d [2] 56 1f [2] 42 04 [2] 4d 1e [2] 53 03 [2] 51 02 [2] 4a 04 [2] 56 03 [2] 4a 2c }

  condition:
    any of them
}