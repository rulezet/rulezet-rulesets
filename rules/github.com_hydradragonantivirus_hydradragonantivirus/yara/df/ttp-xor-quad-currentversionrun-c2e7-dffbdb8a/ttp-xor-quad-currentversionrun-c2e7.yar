rule TTP_XOR_QUAD_CurrentVersionRun_c2e7 {
  strings:
    $key_c2e7 = { 91 88 [2] b5 86 [2] 9e aa [2] b0 88 [2] a4 93 [2] ab 89 [2] b5 94 [2] b7 95 [2] ac 93 [2] b0 94 [2] ac bb }

  condition:
    any of them
}