rule TTP_XOR_QUAD_CurrentVersionRun_bb10 {
  strings:
    $key_bb10 = { e8 7f [2] cc 71 [2] e7 5d [2] c9 7f [2] dd 64 [2] d2 7e [2] cc 63 [2] ce 62 [2] d5 64 [2] c9 63 [2] d5 4c }

  condition:
    any of them
}