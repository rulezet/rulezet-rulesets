rule TTP_XOR_QUAD_CurrentVersionRun_eeae {
  strings:
    $key_eeae = { bd c1 [2] 99 cf [2] b2 e3 [2] 9c c1 [2] 88 da [2] 87 c0 [2] 99 dd [2] 9b dc [2] 80 da [2] 9c dd [2] 80 f2 }

  condition:
    any of them
}