rule TTP_XOR_QUAD_CurrentVersionRun_4cb3 {
  strings:
    $key_4cb3 = { 1f dc [2] 3b d2 [2] 10 fe [2] 3e dc [2] 2a c7 [2] 25 dd [2] 3b c0 [2] 39 c1 [2] 22 c7 [2] 3e c0 [2] 22 ef }

  condition:
    any of them
}