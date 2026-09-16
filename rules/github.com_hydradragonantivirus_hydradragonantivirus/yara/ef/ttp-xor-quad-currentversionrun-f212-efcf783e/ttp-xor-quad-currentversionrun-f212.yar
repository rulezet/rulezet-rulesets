rule TTP_XOR_QUAD_CurrentVersionRun_f212 {
  strings:
    $key_f212 = { a1 7d [2] 85 73 [2] ae 5f [2] 80 7d [2] 94 66 [2] 9b 7c [2] 85 61 [2] 87 60 [2] 9c 66 [2] 80 61 [2] 9c 4e }

  condition:
    any of them
}