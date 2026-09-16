rule TTP_XOR_QUAD_CurrentVersionRun_a70d {
  strings:
    $key_a70d = { f4 62 [2] d0 6c [2] fb 40 [2] d5 62 [2] c1 79 [2] ce 63 [2] d0 7e [2] d2 7f [2] c9 79 [2] d5 7e [2] c9 51 }

  condition:
    any of them
}