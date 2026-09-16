rule TTP_XOR_QUAD_CurrentVersionRun_9bae {
  strings:
    $key_9bae = { c8 c1 [2] ec cf [2] c7 e3 [2] e9 c1 [2] fd da [2] f2 c0 [2] ec dd [2] ee dc [2] f5 da [2] e9 dd [2] f5 f2 }

  condition:
    any of them
}