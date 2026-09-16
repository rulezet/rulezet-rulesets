rule TTP_XOR_QUAD_CurrentVersionRun_b8d8 {
  strings:
    $key_b8d8 = { eb b7 [2] cf b9 [2] e4 95 [2] ca b7 [2] de ac [2] d1 b6 [2] cf ab [2] cd aa [2] d6 ac [2] ca ab [2] d6 84 }

  condition:
    any of them
}