rule TTP_XOR_QUAD_CurrentVersionRun_a010 {
  strings:
    $key_a010 = { f3 7f [2] d7 71 [2] fc 5d [2] d2 7f [2] c6 64 [2] c9 7e [2] d7 63 [2] d5 62 [2] ce 64 [2] d2 63 [2] ce 4c }

  condition:
    any of them
}