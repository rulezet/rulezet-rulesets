rule TTP_XOR_QUAD_CurrentVersionRun_a720 {
  strings:
    $key_a720 = { f4 4f [2] d0 41 [2] fb 6d [2] d5 4f [2] c1 54 [2] ce 4e [2] d0 53 [2] d2 52 [2] c9 54 [2] d5 53 [2] c9 7c }

  condition:
    any of them
}