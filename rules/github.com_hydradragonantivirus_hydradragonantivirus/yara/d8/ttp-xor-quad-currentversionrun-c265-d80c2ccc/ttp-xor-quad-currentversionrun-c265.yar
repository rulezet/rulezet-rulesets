rule TTP_XOR_QUAD_CurrentVersionRun_c265 {
  strings:
    $key_c265 = { 91 0a [2] b5 04 [2] 9e 28 [2] b0 0a [2] a4 11 [2] ab 0b [2] b5 16 [2] b7 17 [2] ac 11 [2] b0 16 [2] ac 39 }

  condition:
    any of them
}