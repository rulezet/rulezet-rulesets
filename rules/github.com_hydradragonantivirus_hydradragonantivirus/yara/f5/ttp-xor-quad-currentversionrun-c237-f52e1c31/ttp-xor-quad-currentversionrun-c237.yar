rule TTP_XOR_QUAD_CurrentVersionRun_c237 {
  strings:
    $key_c237 = { 91 58 [2] b5 56 [2] 9e 7a [2] b0 58 [2] a4 43 [2] ab 59 [2] b5 44 [2] b7 45 [2] ac 43 [2] b0 44 [2] ac 6b }

  condition:
    any of them
}