rule TTP_XOR_QUAD_CurrentVersionRun_f9df {
  strings:
    $key_f9df = { aa b0 [2] 8e be [2] a5 92 [2] 8b b0 [2] 9f ab [2] 90 b1 [2] 8e ac [2] 8c ad [2] 97 ab [2] 8b ac [2] 97 83 }

  condition:
    any of them
}