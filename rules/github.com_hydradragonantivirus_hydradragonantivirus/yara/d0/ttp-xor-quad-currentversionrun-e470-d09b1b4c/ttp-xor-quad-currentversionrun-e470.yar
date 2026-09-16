rule TTP_XOR_QUAD_CurrentVersionRun_e470 {
  strings:
    $key_e470 = { b7 1f [2] 93 11 [2] b8 3d [2] 96 1f [2] 82 04 [2] 8d 1e [2] 93 03 [2] 91 02 [2] 8a 04 [2] 96 03 [2] 8a 2c }

  condition:
    any of them
}