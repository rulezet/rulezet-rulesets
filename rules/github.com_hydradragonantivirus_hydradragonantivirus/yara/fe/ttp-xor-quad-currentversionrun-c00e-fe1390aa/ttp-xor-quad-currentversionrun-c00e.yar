rule TTP_XOR_QUAD_CurrentVersionRun_c00e {
  strings:
    $key_c00e = { 93 61 [2] b7 6f [2] 9c 43 [2] b2 61 [2] a6 7a [2] a9 60 [2] b7 7d [2] b5 7c [2] ae 7a [2] b2 7d [2] ae 52 }

  condition:
    any of them
}