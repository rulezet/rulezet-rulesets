rule TTP_XOR_QUAD_CurrentVersionRun_10e0 {
  strings:
    $key_10e0 = { 43 8f [2] 67 81 [2] 4c ad [2] 62 8f [2] 76 94 [2] 79 8e [2] 67 93 [2] 65 92 [2] 7e 94 [2] 62 93 [2] 7e bc }

  condition:
    any of them
}