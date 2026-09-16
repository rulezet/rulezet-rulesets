rule TTP_XOR_QUAD_CurrentVersionRun_19a9 {
  strings:
    $key_19a9 = { 4a c6 [2] 6e c8 [2] 45 e4 [2] 6b c6 [2] 7f dd [2] 70 c7 [2] 6e da [2] 6c db [2] 77 dd [2] 6b da [2] 77 f5 }

  condition:
    any of them
}