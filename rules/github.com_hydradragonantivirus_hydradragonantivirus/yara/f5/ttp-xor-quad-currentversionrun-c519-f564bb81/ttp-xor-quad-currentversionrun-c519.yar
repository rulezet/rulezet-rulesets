rule TTP_XOR_QUAD_CurrentVersionRun_c519 {
  strings:
    $key_c519 = { 96 76 [2] b2 78 [2] 99 54 [2] b7 76 [2] a3 6d [2] ac 77 [2] b2 6a [2] b0 6b [2] ab 6d [2] b7 6a [2] ab 45 }

  condition:
    any of them
}