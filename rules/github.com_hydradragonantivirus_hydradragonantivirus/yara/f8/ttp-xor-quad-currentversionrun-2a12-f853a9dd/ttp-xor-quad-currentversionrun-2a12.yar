rule TTP_XOR_QUAD_CurrentVersionRun_2a12 {
  strings:
    $key_2a12 = { 79 7d [2] 5d 73 [2] 76 5f [2] 58 7d [2] 4c 66 [2] 43 7c [2] 5d 61 [2] 5f 60 [2] 44 66 [2] 58 61 [2] 44 4e }

  condition:
    any of them
}