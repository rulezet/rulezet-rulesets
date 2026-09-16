rule TTP_XOR_QUAD_CurrentVersionRun_a700 {
  strings:
    $key_a700 = { f4 6f [2] d0 61 [2] fb 4d [2] d5 6f [2] c1 74 [2] ce 6e [2] d0 73 [2] d2 72 [2] c9 74 [2] d5 73 [2] c9 5c }

  condition:
    any of them
}