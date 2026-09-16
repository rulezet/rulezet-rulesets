rule TTP_XOR_QUAD_CurrentVersionRun_19b3 {
  strings:
    $key_19b3 = { 4a dc [2] 6e d2 [2] 45 fe [2] 6b dc [2] 7f c7 [2] 70 dd [2] 6e c0 [2] 6c c1 [2] 77 c7 [2] 6b c0 [2] 77 ef }

  condition:
    any of them
}