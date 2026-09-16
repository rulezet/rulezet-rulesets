rule TTP_XOR_QUAD_CurrentVersionRun_c5e8 {
  strings:
    $key_c5e8 = { 96 87 [2] b2 89 [2] 99 a5 [2] b7 87 [2] a3 9c [2] ac 86 [2] b2 9b [2] b0 9a [2] ab 9c [2] b7 9b [2] ab b4 }

  condition:
    any of them
}