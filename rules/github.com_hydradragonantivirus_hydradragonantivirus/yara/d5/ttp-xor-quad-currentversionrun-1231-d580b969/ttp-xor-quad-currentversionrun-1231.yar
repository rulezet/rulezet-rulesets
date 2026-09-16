rule TTP_XOR_QUAD_CurrentVersionRun_1231 {
  strings:
    $key_1231 = { 41 5e [2] 65 50 [2] 4e 7c [2] 60 5e [2] 74 45 [2] 7b 5f [2] 65 42 [2] 67 43 [2] 7c 45 [2] 60 42 [2] 7c 6d }

  condition:
    any of them
}