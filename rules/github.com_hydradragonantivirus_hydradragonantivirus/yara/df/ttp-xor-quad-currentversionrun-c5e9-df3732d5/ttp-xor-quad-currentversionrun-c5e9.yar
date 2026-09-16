rule TTP_XOR_QUAD_CurrentVersionRun_c5e9 {
  strings:
    $key_c5e9 = { 96 86 [2] b2 88 [2] 99 a4 [2] b7 86 [2] a3 9d [2] ac 87 [2] b2 9a [2] b0 9b [2] ab 9d [2] b7 9a [2] ab b5 }

  condition:
    any of them
}