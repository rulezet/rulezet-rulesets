rule TTP_XOR_QUAD_CurrentVersionRun_76fe {
  strings:
    $key_76fe = { 25 91 [2] 01 9f [2] 2a b3 [2] 04 91 [2] 10 8a [2] 1f 90 [2] 01 8d [2] 03 8c [2] 18 8a [2] 04 8d [2] 18 a2 }

  condition:
    any of them
}