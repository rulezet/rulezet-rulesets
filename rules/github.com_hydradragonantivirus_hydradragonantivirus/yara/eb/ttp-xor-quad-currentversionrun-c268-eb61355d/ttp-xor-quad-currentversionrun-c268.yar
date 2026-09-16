rule TTP_XOR_QUAD_CurrentVersionRun_c268 {
  strings:
    $key_c268 = { 91 07 [2] b5 09 [2] 9e 25 [2] b0 07 [2] a4 1c [2] ab 06 [2] b5 1b [2] b7 1a [2] ac 1c [2] b0 1b [2] ac 34 }

  condition:
    any of them
}