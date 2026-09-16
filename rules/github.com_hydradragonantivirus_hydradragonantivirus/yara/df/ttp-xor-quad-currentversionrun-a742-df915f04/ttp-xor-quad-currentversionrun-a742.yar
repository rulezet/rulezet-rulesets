rule TTP_XOR_QUAD_CurrentVersionRun_a742 {
  strings:
    $key_a742 = { f4 2d [2] d0 23 [2] fb 0f [2] d5 2d [2] c1 36 [2] ce 2c [2] d0 31 [2] d2 30 [2] c9 36 [2] d5 31 [2] c9 1e }

  condition:
    any of them
}