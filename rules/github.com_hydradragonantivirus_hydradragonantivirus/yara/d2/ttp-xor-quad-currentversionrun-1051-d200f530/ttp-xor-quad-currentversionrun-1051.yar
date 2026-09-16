rule TTP_XOR_QUAD_CurrentVersionRun_1051 {
  strings:
    $key_1051 = { 43 3e [2] 67 30 [2] 4c 1c [2] 62 3e [2] 76 25 [2] 79 3f [2] 67 22 [2] 65 23 [2] 7e 25 [2] 62 22 [2] 7e 0d }

  condition:
    any of them
}