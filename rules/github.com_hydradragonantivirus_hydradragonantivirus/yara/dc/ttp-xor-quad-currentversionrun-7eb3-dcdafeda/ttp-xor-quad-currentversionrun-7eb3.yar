rule TTP_XOR_QUAD_CurrentVersionRun_7eb3 {
  strings:
    $key_7eb3 = { 2d dc [2] 09 d2 [2] 22 fe [2] 0c dc [2] 18 c7 [2] 17 dd [2] 09 c0 [2] 0b c1 [2] 10 c7 [2] 0c c0 [2] 10 ef }

  condition:
    any of them
}