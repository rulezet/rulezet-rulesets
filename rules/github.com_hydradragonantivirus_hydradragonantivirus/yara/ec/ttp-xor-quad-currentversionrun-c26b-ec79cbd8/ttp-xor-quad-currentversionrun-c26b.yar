rule TTP_XOR_QUAD_CurrentVersionRun_c26b {
  strings:
    $key_c26b = { 91 04 [2] b5 0a [2] 9e 26 [2] b0 04 [2] a4 1f [2] ab 05 [2] b5 18 [2] b7 19 [2] ac 1f [2] b0 18 [2] ac 37 }

  condition:
    any of them
}