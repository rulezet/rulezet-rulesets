rule TTP_XOR_QUAD_CurrentVersionRun_6fae {
  strings:
    $key_6fae = { 3c c1 [2] 18 cf [2] 33 e3 [2] 1d c1 [2] 09 da [2] 06 c0 [2] 18 dd [2] 1a dc [2] 01 da [2] 1d dd [2] 01 f2 }

  condition:
    any of them
}