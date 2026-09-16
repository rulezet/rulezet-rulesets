rule TTP_XOR_QUAD_CurrentVersionRun_c729 {
  strings:
    $key_c729 = { 94 46 [2] b0 48 [2] 9b 64 [2] b5 46 [2] a1 5d [2] ae 47 [2] b0 5a [2] b2 5b [2] a9 5d [2] b5 5a [2] a9 75 }

  condition:
    any of them
}