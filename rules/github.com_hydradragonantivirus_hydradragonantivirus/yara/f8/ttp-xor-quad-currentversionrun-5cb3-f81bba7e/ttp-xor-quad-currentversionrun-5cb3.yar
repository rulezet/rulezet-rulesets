rule TTP_XOR_QUAD_CurrentVersionRun_5cb3 {
  strings:
    $key_5cb3 = { 0f dc [2] 2b d2 [2] 00 fe [2] 2e dc [2] 3a c7 [2] 35 dd [2] 2b c0 [2] 29 c1 [2] 32 c7 [2] 2e c0 [2] 32 ef }

  condition:
    any of them
}