rule TTP_XOR_QUAD_CurrentVersionRun_2eb3 {
  strings:
    $key_2eb3 = { 7d dc [2] 59 d2 [2] 72 fe [2] 5c dc [2] 48 c7 [2] 47 dd [2] 59 c0 [2] 5b c1 [2] 40 c7 [2] 5c c0 [2] 40 ef }

  condition:
    any of them
}