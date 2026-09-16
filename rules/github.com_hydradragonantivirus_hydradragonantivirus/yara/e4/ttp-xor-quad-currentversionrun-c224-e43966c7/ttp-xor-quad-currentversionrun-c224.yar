rule TTP_XOR_QUAD_CurrentVersionRun_c224 {
  strings:
    $key_c224 = { 91 4b [2] b5 45 [2] 9e 69 [2] b0 4b [2] a4 50 [2] ab 4a [2] b5 57 [2] b7 56 [2] ac 50 [2] b0 57 [2] ac 78 }

  condition:
    any of them
}