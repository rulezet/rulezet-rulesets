rule TTP_XOR_QUAD_CurrentVersionRun_bb32 {
  strings:
    $key_bb32 = { e8 5d [2] cc 53 [2] e7 7f [2] c9 5d [2] dd 46 [2] d2 5c [2] cc 41 [2] ce 40 [2] d5 46 [2] c9 41 [2] d5 6e }

  condition:
    any of them
}