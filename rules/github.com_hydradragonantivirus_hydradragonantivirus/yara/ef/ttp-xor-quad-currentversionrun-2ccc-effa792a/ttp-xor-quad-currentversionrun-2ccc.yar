rule TTP_XOR_QUAD_CurrentVersionRun_2ccc {
  strings:
    $key_2ccc = { 7f a3 [2] 5b ad [2] 70 81 [2] 5e a3 [2] 4a b8 [2] 45 a2 [2] 5b bf [2] 59 be [2] 42 b8 [2] 5e bf [2] 42 90 }

  condition:
    any of them
}