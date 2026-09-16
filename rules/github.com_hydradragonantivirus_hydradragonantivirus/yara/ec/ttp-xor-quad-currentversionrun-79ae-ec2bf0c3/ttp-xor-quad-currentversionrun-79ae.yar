rule TTP_XOR_QUAD_CurrentVersionRun_79ae {
  strings:
    $key_79ae = { 2a c1 [2] 0e cf [2] 25 e3 [2] 0b c1 [2] 1f da [2] 10 c0 [2] 0e dd [2] 0c dc [2] 17 da [2] 0b dd [2] 17 f2 }

  condition:
    any of them
}