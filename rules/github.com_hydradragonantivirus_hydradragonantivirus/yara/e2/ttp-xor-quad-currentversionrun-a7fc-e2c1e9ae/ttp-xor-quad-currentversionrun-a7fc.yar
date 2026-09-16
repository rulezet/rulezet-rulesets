rule TTP_XOR_QUAD_CurrentVersionRun_a7fc {
  strings:
    $key_a7fc = { f4 93 [2] d0 9d [2] fb b1 [2] d5 93 [2] c1 88 [2] ce 92 [2] d0 8f [2] d2 8e [2] c9 88 [2] d5 8f [2] c9 a0 }

  condition:
    any of them
}