rule TTP_XOR_QUAD_CurrentVersionRun_39fd {
  strings:
    $key_39fd = { 6a 92 [2] 4e 9c [2] 65 b0 [2] 4b 92 [2] 5f 89 [2] 50 93 [2] 4e 8e [2] 4c 8f [2] 57 89 [2] 4b 8e [2] 57 a1 }

  condition:
    any of them
}