rule TTP_XOR_QUAD_CurrentVersionRun_e0ae {
  strings:
    $key_e0ae = { b3 c1 [2] 97 cf [2] bc e3 [2] 92 c1 [2] 86 da [2] 89 c0 [2] 97 dd [2] 95 dc [2] 8e da [2] 92 dd [2] 8e f2 }

  condition:
    any of them
}