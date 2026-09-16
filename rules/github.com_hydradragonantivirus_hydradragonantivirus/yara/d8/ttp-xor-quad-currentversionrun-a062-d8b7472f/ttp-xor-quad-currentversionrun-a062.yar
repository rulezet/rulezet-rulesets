rule TTP_XOR_QUAD_CurrentVersionRun_a062 {
  strings:
    $key_a062 = { f3 0d [2] d7 03 [2] fc 2f [2] d2 0d [2] c6 16 [2] c9 0c [2] d7 11 [2] d5 10 [2] ce 16 [2] d2 11 [2] ce 3e }

  condition:
    any of them
}