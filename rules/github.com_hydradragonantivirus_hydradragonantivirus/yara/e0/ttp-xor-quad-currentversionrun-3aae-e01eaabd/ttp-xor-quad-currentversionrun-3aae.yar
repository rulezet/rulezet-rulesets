rule TTP_XOR_QUAD_CurrentVersionRun_3aae {
  strings:
    $key_3aae = { 69 c1 [2] 4d cf [2] 66 e3 [2] 48 c1 [2] 5c da [2] 53 c0 [2] 4d dd [2] 4f dc [2] 54 da [2] 48 dd [2] 54 f2 }

  condition:
    any of them
}