rule TTP_XOR_QUAD_CurrentVersionRun_ebcc {
  strings:
    $key_ebcc = { b8 a3 [2] 9c ad [2] b7 81 [2] 99 a3 [2] 8d b8 [2] 82 a2 [2] 9c bf [2] 9e be [2] 85 b8 [2] 99 bf [2] 85 90 }

  condition:
    any of them
}