rule TTP_XOR_QUAD_CurrentVersionRun_c31f {
  strings:
    $key_c31f = { 90 70 [2] b4 7e [2] 9f 52 [2] b1 70 [2] a5 6b [2] aa 71 [2] b4 6c [2] b6 6d [2] ad 6b [2] b1 6c [2] ad 43 }

  condition:
    any of them
}