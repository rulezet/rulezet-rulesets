rule TTP_XOR_QUAD_CurrentVersionRun_05aa {
  strings:
    $key_05aa = { 56 c5 [2] 72 cb [2] 59 e7 [2] 77 c5 [2] 63 de [2] 6c c4 [2] 72 d9 [2] 70 d8 [2] 6b de [2] 77 d9 [2] 6b f6 }

  condition:
    any of them
}