rule TTP_XOR_QUAD_CurrentVersionRun_a07e {
  strings:
    $key_a07e = { f3 11 [2] d7 1f [2] fc 33 [2] d2 11 [2] c6 0a [2] c9 10 [2] d7 0d [2] d5 0c [2] ce 0a [2] d2 0d [2] ce 22 }

  condition:
    any of them
}