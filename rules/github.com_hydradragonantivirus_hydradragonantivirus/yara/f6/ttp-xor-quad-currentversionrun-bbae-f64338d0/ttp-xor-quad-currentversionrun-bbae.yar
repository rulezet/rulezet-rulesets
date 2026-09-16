rule TTP_XOR_QUAD_CurrentVersionRun_bbae {
  strings:
    $key_bbae = { e8 c1 [2] cc cf [2] e7 e3 [2] c9 c1 [2] dd da [2] d2 c0 [2] cc dd [2] ce dc [2] d5 da [2] c9 dd [2] d5 f2 }

  condition:
    any of them
}