rule TTP_XOR_QUAD_CurrentVersionRun_65fd {
  strings:
    $key_65fd = { 36 92 [2] 12 9c [2] 39 b0 [2] 17 92 [2] 03 89 [2] 0c 93 [2] 12 8e [2] 10 8f [2] 0b 89 [2] 17 8e [2] 0b a1 }

  condition:
    any of them
}