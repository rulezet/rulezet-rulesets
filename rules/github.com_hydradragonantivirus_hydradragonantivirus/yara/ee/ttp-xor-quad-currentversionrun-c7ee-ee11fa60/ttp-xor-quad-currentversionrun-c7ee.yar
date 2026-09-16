rule TTP_XOR_QUAD_CurrentVersionRun_c7ee {
  strings:
    $key_c7ee = { 94 81 [2] b0 8f [2] 9b a3 [2] b5 81 [2] a1 9a [2] ae 80 [2] b0 9d [2] b2 9c [2] a9 9a [2] b5 9d [2] a9 b2 }

  condition:
    any of them
}