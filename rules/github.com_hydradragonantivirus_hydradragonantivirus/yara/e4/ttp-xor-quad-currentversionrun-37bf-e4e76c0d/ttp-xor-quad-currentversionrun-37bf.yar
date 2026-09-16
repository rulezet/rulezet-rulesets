rule TTP_XOR_QUAD_CurrentVersionRun_37bf {
  strings:
    $key_37bf = { 64 d0 [2] 40 de [2] 6b f2 [2] 45 d0 [2] 51 cb [2] 5e d1 [2] 40 cc [2] 42 cd [2] 59 cb [2] 45 cc [2] 59 e3 }

  condition:
    any of them
}