rule TTP_XOR_QUAD_CurrentVersionRun_09ae {
  strings:
    $key_09ae = { 5a c1 [2] 7e cf [2] 55 e3 [2] 7b c1 [2] 6f da [2] 60 c0 [2] 7e dd [2] 7c dc [2] 67 da [2] 7b dd [2] 67 f2 }

  condition:
    any of them
}