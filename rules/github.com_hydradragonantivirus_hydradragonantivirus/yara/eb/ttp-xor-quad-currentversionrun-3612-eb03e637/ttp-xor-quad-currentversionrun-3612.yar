rule TTP_XOR_QUAD_CurrentVersionRun_3612 {
  strings:
    $key_3612 = { 65 7d [2] 41 73 [2] 6a 5f [2] 44 7d [2] 50 66 [2] 5f 7c [2] 41 61 [2] 43 60 [2] 58 66 [2] 44 61 [2] 58 4e }

  condition:
    any of them
}