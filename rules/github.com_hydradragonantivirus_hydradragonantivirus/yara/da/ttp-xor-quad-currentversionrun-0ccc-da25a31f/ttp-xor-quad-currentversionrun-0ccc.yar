rule TTP_XOR_QUAD_CurrentVersionRun_0ccc {
  strings:
    $key_0ccc = { 5f a3 [2] 7b ad [2] 50 81 [2] 7e a3 [2] 6a b8 [2] 65 a2 [2] 7b bf [2] 79 be [2] 62 b8 [2] 7e bf [2] 62 90 }

  condition:
    any of them
}