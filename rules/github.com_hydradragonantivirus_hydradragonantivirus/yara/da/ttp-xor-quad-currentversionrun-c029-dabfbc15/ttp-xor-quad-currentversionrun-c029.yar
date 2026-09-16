rule TTP_XOR_QUAD_CurrentVersionRun_c029 {
  strings:
    $key_c029 = { 93 46 [2] b7 48 [2] 9c 64 [2] b2 46 [2] a6 5d [2] a9 47 [2] b7 5a [2] b5 5b [2] ae 5d [2] b2 5a [2] ae 75 }

  condition:
    any of them
}