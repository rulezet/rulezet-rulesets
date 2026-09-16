rule TTP_XOR_QUAD_CurrentVersionRun_37b5 {
  strings:
    $key_37b5 = { 64 da [2] 40 d4 [2] 6b f8 [2] 45 da [2] 51 c1 [2] 5e db [2] 40 c6 [2] 42 c7 [2] 59 c1 [2] 45 c6 [2] 59 e9 }

  condition:
    any of them
}