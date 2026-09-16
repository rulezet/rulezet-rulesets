rule TTP_XOR_QUAD_CurrentVersionRun_5ccc {
  strings:
    $key_5ccc = { 0f a3 [2] 2b ad [2] 00 81 [2] 2e a3 [2] 3a b8 [2] 35 a2 [2] 2b bf [2] 29 be [2] 32 b8 [2] 2e bf [2] 32 90 }

  condition:
    any of them
}