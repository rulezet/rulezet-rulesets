rule TTP_XOR_QUAD_CurrentVersionRun_3ccc {
  strings:
    $key_3ccc = { 6f a3 [2] 4b ad [2] 60 81 [2] 4e a3 [2] 5a b8 [2] 55 a2 [2] 4b bf [2] 49 be [2] 52 b8 [2] 4e bf [2] 52 90 }

  condition:
    any of them
}