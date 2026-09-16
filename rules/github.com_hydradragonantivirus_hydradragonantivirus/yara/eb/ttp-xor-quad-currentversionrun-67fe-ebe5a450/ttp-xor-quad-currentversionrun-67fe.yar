rule TTP_XOR_QUAD_CurrentVersionRun_67fe {
  strings:
    $key_67fe = { 34 91 [2] 10 9f [2] 3b b3 [2] 15 91 [2] 01 8a [2] 0e 90 [2] 10 8d [2] 12 8c [2] 09 8a [2] 15 8d [2] 09 a2 }

  condition:
    any of them
}