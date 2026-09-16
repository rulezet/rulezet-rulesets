rule TTP_XOR_QUAD_CurrentVersionRun_37ba {
  strings:
    $key_37ba = { 64 d5 [2] 40 db [2] 6b f7 [2] 45 d5 [2] 51 ce [2] 5e d4 [2] 40 c9 [2] 42 c8 [2] 59 ce [2] 45 c9 [2] 59 e6 }

  condition:
    any of them
}