rule TTP_XOR_QUAD_CurrentVersionRun_a0eb {
  strings:
    $key_a0eb = { f3 84 [2] d7 8a [2] fc a6 [2] d2 84 [2] c6 9f [2] c9 85 [2] d7 98 [2] d5 99 [2] ce 9f [2] d2 98 [2] ce b7 }

  condition:
    any of them
}