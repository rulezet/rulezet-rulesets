rule TTP_XOR_QUAD_CurrentVersionRun_c270 {
  strings:
    $key_c270 = { 91 1f [2] b5 11 [2] 9e 3d [2] b0 1f [2] a4 04 [2] ab 1e [2] b5 03 [2] b7 02 [2] ac 04 [2] b0 03 [2] ac 2c }

  condition:
    any of them
}