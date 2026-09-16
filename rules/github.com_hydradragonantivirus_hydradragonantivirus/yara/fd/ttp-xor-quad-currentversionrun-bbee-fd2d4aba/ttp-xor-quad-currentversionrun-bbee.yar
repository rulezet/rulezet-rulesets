rule TTP_XOR_QUAD_CurrentVersionRun_bbee {
  strings:
    $key_bbee = { e8 81 [2] cc 8f [2] e7 a3 [2] c9 81 [2] dd 9a [2] d2 80 [2] cc 9d [2] ce 9c [2] d5 9a [2] c9 9d [2] d5 b2 }

  condition:
    any of them
}