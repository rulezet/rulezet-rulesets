rule TTP_XOR_QUAD_CurrentVersionRun_a751 {
  strings:
    $key_a751 = { f4 3e [2] d0 30 [2] fb 1c [2] d5 3e [2] c1 25 [2] ce 3f [2] d0 22 [2] d2 23 [2] c9 25 [2] d5 22 [2] c9 0d }

  condition:
    any of them
}