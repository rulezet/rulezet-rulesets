rule TTP_XOR_QUAD_CurrentVersionRun_a000 {
  strings:
    $key_a000 = { f3 6f [2] d7 61 [2] fc 4d [2] d2 6f [2] c6 74 [2] c9 6e [2] d7 73 [2] d5 72 [2] ce 74 [2] d2 73 [2] ce 5c }

  condition:
    any of them
}