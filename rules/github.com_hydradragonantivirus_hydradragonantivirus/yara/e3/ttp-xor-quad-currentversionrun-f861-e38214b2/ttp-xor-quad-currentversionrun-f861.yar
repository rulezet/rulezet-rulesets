rule TTP_XOR_QUAD_CurrentVersionRun_f861 {
  strings:
    $key_f861 = { ab 0e [2] 8f 00 [2] a4 2c [2] 8a 0e [2] 9e 15 [2] 91 0f [2] 8f 12 [2] 8d 13 [2] 96 15 [2] 8a 12 [2] 96 3d }

  condition:
    any of them
}