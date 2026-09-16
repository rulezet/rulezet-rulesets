rule TTP_XOR_QUAD_CurrentVersionRun_a0f0 {
  strings:
    $key_a0f0 = { f3 9f [2] d7 91 [2] fc bd [2] d2 9f [2] c6 84 [2] c9 9e [2] d7 83 [2] d5 82 [2] ce 84 [2] d2 83 [2] ce ac }

  condition:
    any of them
}