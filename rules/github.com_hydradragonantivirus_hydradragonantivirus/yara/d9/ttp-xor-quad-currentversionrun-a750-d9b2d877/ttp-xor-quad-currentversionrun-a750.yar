rule TTP_XOR_QUAD_CurrentVersionRun_a750 {
  strings:
    $key_a750 = { f4 3f [2] d0 31 [2] fb 1d [2] d5 3f [2] c1 24 [2] ce 3e [2] d0 23 [2] d2 22 [2] c9 24 [2] d5 23 [2] c9 0c }

  condition:
    any of them
}