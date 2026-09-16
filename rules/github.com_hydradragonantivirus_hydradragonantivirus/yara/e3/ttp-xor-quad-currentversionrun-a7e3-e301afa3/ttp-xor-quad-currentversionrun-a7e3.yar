rule TTP_XOR_QUAD_CurrentVersionRun_a7e3 {
  strings:
    $key_a7e3 = { f4 8c [2] d0 82 [2] fb ae [2] d5 8c [2] c1 97 [2] ce 8d [2] d0 90 [2] d2 91 [2] c9 97 [2] d5 90 [2] c9 bf }

  condition:
    any of them
}