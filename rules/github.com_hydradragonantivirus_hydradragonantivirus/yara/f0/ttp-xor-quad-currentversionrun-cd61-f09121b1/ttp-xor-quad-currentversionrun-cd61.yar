rule TTP_XOR_QUAD_CurrentVersionRun_cd61 {
  strings:
    $key_cd61 = { 9e 0e [2] ba 00 [2] 91 2c [2] bf 0e [2] ab 15 [2] a4 0f [2] ba 12 [2] b8 13 [2] a3 15 [2] bf 12 [2] a3 3d }

  condition:
    any of them
}