rule TTP_XOR_QUAD_CurrentVersionRun_c448 {
  strings:
    $key_c448 = { 97 27 [2] b3 29 [2] 98 05 [2] b6 27 [2] a2 3c [2] ad 26 [2] b3 3b [2] b1 3a [2] aa 3c [2] b6 3b [2] aa 14 }

  condition:
    any of them
}