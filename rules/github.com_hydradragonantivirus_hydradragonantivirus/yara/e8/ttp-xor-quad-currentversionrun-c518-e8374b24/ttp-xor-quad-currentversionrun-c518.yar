rule TTP_XOR_QUAD_CurrentVersionRun_c518 {
  strings:
    $key_c518 = { 96 77 [2] b2 79 [2] 99 55 [2] b7 77 [2] a3 6c [2] ac 76 [2] b2 6b [2] b0 6a [2] ab 6c [2] b7 6b [2] ab 44 }

  condition:
    any of them
}