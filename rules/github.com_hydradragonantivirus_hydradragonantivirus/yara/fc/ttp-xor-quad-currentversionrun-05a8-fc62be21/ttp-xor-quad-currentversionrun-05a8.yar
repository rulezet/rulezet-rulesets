rule TTP_XOR_QUAD_CurrentVersionRun_05a8 {
  strings:
    $key_05a8 = { 56 c7 [2] 72 c9 [2] 59 e5 [2] 77 c7 [2] 63 dc [2] 6c c6 [2] 72 db [2] 70 da [2] 6b dc [2] 77 db [2] 6b f4 }

  condition:
    any of them
}