rule TTP_XOR_QUAD_CurrentVersionRun_e670 {
  strings:
    $key_e670 = { b5 1f [2] 91 11 [2] ba 3d [2] 94 1f [2] 80 04 [2] 8f 1e [2] 91 03 [2] 93 02 [2] 88 04 [2] 94 03 [2] 88 2c }

  condition:
    any of them
}