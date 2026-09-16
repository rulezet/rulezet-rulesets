rule TTP_XOR_QUAD_CurrentVersionRun_939a {
  strings:
    $key_939a = { c0 f5 [2] e4 fb [2] cf d7 [2] e1 f5 [2] f5 ee [2] fa f4 [2] e4 e9 [2] e6 e8 [2] fd ee [2] e1 e9 [2] fd c6 }

  condition:
    any of them
}