rule TTP_XOR_QUAD_CurrentVersionRun_699a {
  strings:
    $key_699a = { 3a f5 [2] 1e fb [2] 35 d7 [2] 1b f5 [2] 0f ee [2] 00 f4 [2] 1e e9 [2] 1c e8 [2] 07 ee [2] 1b e9 [2] 07 c6 }

  condition:
    any of them
}