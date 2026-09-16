rule TTP_XOR_QUAD_CurrentVersionRun_1736 {
  strings:
    $key_1736 = { 44 59 [2] 60 57 [2] 4b 7b [2] 65 59 [2] 71 42 [2] 7e 58 [2] 60 45 [2] 62 44 [2] 79 42 [2] 65 45 [2] 79 6a }

  condition:
    any of them
}