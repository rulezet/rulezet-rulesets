rule TTP_XOR_QUAD_CurrentVersionRun_1262 {
  strings:
    $key_1262 = { 41 0d [2] 65 03 [2] 4e 2f [2] 60 0d [2] 74 16 [2] 7b 0c [2] 65 11 [2] 67 10 [2] 7c 16 [2] 60 11 [2] 7c 3e }

  condition:
    any of them
}