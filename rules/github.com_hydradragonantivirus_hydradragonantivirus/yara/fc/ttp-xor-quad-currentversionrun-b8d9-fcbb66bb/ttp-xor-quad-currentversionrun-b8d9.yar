rule TTP_XOR_QUAD_CurrentVersionRun_b8d9 {
  strings:
    $key_b8d9 = { eb b6 [2] cf b8 [2] e4 94 [2] ca b6 [2] de ad [2] d1 b7 [2] cf aa [2] cd ab [2] d6 ad [2] ca aa [2] d6 85 }

  condition:
    any of them
}