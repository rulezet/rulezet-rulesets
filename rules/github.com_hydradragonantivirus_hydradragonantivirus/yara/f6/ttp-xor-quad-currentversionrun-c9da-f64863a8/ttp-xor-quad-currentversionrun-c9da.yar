rule TTP_XOR_QUAD_CurrentVersionRun_c9da {
  strings:
    $key_c9da = { 9a b5 [2] be bb [2] 95 97 [2] bb b5 [2] af ae [2] a0 b4 [2] be a9 [2] bc a8 [2] a7 ae [2] bb a9 [2] a7 86 }

  condition:
    any of them
}