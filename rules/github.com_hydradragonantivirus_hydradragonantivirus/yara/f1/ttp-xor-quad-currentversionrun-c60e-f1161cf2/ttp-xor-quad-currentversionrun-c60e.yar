rule TTP_XOR_QUAD_CurrentVersionRun_c60e {
  strings:
    $key_c60e = { 95 61 [2] b1 6f [2] 9a 43 [2] b4 61 [2] a0 7a [2] af 60 [2] b1 7d [2] b3 7c [2] a8 7a [2] b4 7d [2] a8 52 }

  condition:
    any of them
}