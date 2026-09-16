rule TTP_XOR_QUAD_CurrentVersionRun_bfc5 {
  strings:
    $key_bfc5 = { ec aa [2] c8 a4 [2] e3 88 [2] cd aa [2] d9 b1 [2] d6 ab [2] c8 b6 [2] ca b7 [2] d1 b1 [2] cd b6 [2] d1 99 }

  condition:
    any of them
}