rule TTP_XOR_QUAD_CurrentVersionRun_7aae {
  strings:
    $key_7aae = { 29 c1 [2] 0d cf [2] 26 e3 [2] 08 c1 [2] 1c da [2] 13 c0 [2] 0d dd [2] 0f dc [2] 14 da [2] 08 dd [2] 14 f2 }

  condition:
    any of them
}