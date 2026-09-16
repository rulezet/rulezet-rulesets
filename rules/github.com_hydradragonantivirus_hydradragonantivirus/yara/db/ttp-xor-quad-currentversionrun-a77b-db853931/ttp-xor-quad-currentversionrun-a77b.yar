rule TTP_XOR_QUAD_CurrentVersionRun_a77b {
  strings:
    $key_a77b = { f4 14 [2] d0 1a [2] fb 36 [2] d5 14 [2] c1 0f [2] ce 15 [2] d0 08 [2] d2 09 [2] c9 0f [2] d5 08 [2] c9 27 }

  condition:
    any of them
}