rule TTP_XOR_QUAD_CurrentVersionRun_a7c5 {
  strings:
    $key_a7c5 = { f4 aa [2] d0 a4 [2] fb 88 [2] d5 aa [2] c1 b1 [2] ce ab [2] d0 b6 [2] d2 b7 [2] c9 b1 [2] d5 b6 [2] c9 99 }

  condition:
    any of them
}