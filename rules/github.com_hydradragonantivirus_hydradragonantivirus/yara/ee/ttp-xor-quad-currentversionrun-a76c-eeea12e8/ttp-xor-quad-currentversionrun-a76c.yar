rule TTP_XOR_QUAD_CurrentVersionRun_a76c {
  strings:
    $key_a76c = { f4 03 [2] d0 0d [2] fb 21 [2] d5 03 [2] c1 18 [2] ce 02 [2] d0 1f [2] d2 1e [2] c9 18 [2] d5 1f [2] c9 30 }

  condition:
    any of them
}