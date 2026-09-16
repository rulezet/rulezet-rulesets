rule TTP_XOR_QUAD_CurrentVersionRun_b6c5 {
  strings:
    $key_b6c5 = { e5 aa [2] c1 a4 [2] ea 88 [2] c4 aa [2] d0 b1 [2] df ab [2] c1 b6 [2] c3 b7 [2] d8 b1 [2] c4 b6 [2] d8 99 }

  condition:
    any of them
}