rule TTP_XOR_QUAD_CurrentVersionRun_8bae {
  strings:
    $key_8bae = { d8 c1 [2] fc cf [2] d7 e3 [2] f9 c1 [2] ed da [2] e2 c0 [2] fc dd [2] fe dc [2] e5 da [2] f9 dd [2] e5 f2 }

  condition:
    any of them
}