rule TTP_XOR_QUAD_CurrentVersionRun_b9df {
  strings:
    $key_b9df = { ea b0 [2] ce be [2] e5 92 [2] cb b0 [2] df ab [2] d0 b1 [2] ce ac [2] cc ad [2] d7 ab [2] cb ac [2] d7 83 }

  condition:
    any of them
}