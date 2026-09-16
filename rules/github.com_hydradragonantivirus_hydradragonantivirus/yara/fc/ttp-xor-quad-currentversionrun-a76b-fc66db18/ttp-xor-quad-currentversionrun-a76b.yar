rule TTP_XOR_QUAD_CurrentVersionRun_a76b {
  strings:
    $key_a76b = { f4 04 [2] d0 0a [2] fb 26 [2] d5 04 [2] c1 1f [2] ce 05 [2] d0 18 [2] d2 19 [2] c9 1f [2] d5 18 [2] c9 37 }

  condition:
    any of them
}