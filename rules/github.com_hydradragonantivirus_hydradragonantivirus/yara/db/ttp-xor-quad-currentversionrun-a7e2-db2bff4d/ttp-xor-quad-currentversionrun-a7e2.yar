rule TTP_XOR_QUAD_CurrentVersionRun_a7e2 {
  strings:
    $key_a7e2 = { f4 8d [2] d0 83 [2] fb af [2] d5 8d [2] c1 96 [2] ce 8c [2] d0 91 [2] d2 90 [2] c9 96 [2] d5 91 [2] c9 be }

  condition:
    any of them
}