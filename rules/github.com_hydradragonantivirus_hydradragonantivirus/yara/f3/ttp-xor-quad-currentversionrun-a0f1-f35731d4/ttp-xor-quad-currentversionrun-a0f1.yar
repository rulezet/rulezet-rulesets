rule TTP_XOR_QUAD_CurrentVersionRun_a0f1 {
  strings:
    $key_a0f1 = { f3 9e [2] d7 90 [2] fc bc [2] d2 9e [2] c6 85 [2] c9 9f [2] d7 82 [2] d5 83 [2] ce 85 [2] d2 82 [2] ce ad }

  condition:
    any of them
}