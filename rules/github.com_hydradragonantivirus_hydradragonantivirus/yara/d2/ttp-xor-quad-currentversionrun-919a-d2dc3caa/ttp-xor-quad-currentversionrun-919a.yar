rule TTP_XOR_QUAD_CurrentVersionRun_919a {
  strings:
    $key_919a = { c2 f5 [2] e6 fb [2] cd d7 [2] e3 f5 [2] f7 ee [2] f8 f4 [2] e6 e9 [2] e4 e8 [2] ff ee [2] e3 e9 [2] ff c6 }

  condition:
    any of them
}