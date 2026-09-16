rule TTP_XOR_QUAD_CurrentVersionRun_fcdb {
  strings:
    $key_fcdb = { af b4 [2] 8b ba [2] a0 96 [2] 8e b4 [2] 9a af [2] 95 b5 [2] 8b a8 [2] 89 a9 [2] 92 af [2] 8e a8 [2] 92 87 }

  condition:
    any of them
}