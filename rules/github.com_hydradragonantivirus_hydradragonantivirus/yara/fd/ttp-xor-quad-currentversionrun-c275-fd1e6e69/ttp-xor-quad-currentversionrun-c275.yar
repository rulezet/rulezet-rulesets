rule TTP_XOR_QUAD_CurrentVersionRun_c275 {
  strings:
    $key_c275 = { 91 1a [2] b5 14 [2] 9e 38 [2] b0 1a [2] a4 01 [2] ab 1b [2] b5 06 [2] b7 07 [2] ac 01 [2] b0 06 [2] ac 29 }

  condition:
    any of them
}