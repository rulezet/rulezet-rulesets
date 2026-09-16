rule TTP_XOR_QUAD_CurrentVersionRun_a07a {
  strings:
    $key_a07a = { f3 15 [2] d7 1b [2] fc 37 [2] d2 15 [2] c6 0e [2] c9 14 [2] d7 09 [2] d5 08 [2] ce 0e [2] d2 09 [2] ce 26 }

  condition:
    any of them
}