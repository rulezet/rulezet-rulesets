rule TTP_XOR_QUAD_CurrentVersionRun_94a9 {
  strings:
    $key_94a9 = { c7 c6 [2] e3 c8 [2] c8 e4 [2] e6 c6 [2] f2 dd [2] fd c7 [2] e3 da [2] e1 db [2] fa dd [2] e6 da [2] fa f5 }

  condition:
    any of them
}