rule TTP_XOR_QUAD_CurrentVersionRun_0e22 {
  strings:
    $key_0e22 = { 5d 4d [2] 79 43 [2] 52 6f [2] 7c 4d [2] 68 56 [2] 67 4c [2] 79 51 [2] 7b 50 [2] 60 56 [2] 7c 51 [2] 60 7e }

  condition:
    any of them
}