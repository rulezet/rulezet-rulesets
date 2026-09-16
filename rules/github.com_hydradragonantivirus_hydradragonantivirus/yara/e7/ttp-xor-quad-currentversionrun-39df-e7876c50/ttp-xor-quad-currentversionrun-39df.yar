rule TTP_XOR_QUAD_CurrentVersionRun_39df {
  strings:
    $key_39df = { 6a b0 [2] 4e be [2] 65 92 [2] 4b b0 [2] 5f ab [2] 50 b1 [2] 4e ac [2] 4c ad [2] 57 ab [2] 4b ac [2] 57 83 }

  condition:
    any of them
}