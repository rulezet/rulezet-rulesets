rule TTP_XOR_QUAD_CurrentVersionRun_a099 {
  strings:
    $key_a099 = { f3 f6 [2] d7 f8 [2] fc d4 [2] d2 f6 [2] c6 ed [2] c9 f7 [2] d7 ea [2] d5 eb [2] ce ed [2] d2 ea [2] ce c5 }

  condition:
    any of them
}