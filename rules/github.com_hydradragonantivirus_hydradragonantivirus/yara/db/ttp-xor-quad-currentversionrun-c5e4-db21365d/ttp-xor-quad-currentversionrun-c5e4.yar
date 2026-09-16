rule TTP_XOR_QUAD_CurrentVersionRun_c5e4 {
  strings:
    $key_c5e4 = { 96 8b [2] b2 85 [2] 99 a9 [2] b7 8b [2] a3 90 [2] ac 8a [2] b2 97 [2] b0 96 [2] ab 90 [2] b7 97 [2] ab b8 }

  condition:
    any of them
}