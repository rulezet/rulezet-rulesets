rule TTP_XOR_QUAD_CurrentVersionRun_a7f6 {
  strings:
    $key_a7f6 = { f4 99 [2] d0 97 [2] fb bb [2] d5 99 [2] c1 82 [2] ce 98 [2] d0 85 [2] d2 84 [2] c9 82 [2] d5 85 [2] c9 aa }

  condition:
    any of them
}