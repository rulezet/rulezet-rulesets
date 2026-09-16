rule TTP_XOR_QUAD_CurrentVersionRun_c2d7 {
  strings:
    $key_c2d7 = { 91 b8 [2] b5 b6 [2] 9e 9a [2] b0 b8 [2] a4 a3 [2] ab b9 [2] b5 a4 [2] b7 a5 [2] ac a3 [2] b0 a4 [2] ac 8b }

  condition:
    any of them
}