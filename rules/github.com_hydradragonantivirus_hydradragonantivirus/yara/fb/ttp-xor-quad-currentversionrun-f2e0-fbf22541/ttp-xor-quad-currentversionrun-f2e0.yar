rule TTP_XOR_QUAD_CurrentVersionRun_f2e0 {
  strings:
    $key_f2e0 = { a1 8f [2] 85 81 [2] ae ad [2] 80 8f [2] 94 94 [2] 9b 8e [2] 85 93 [2] 87 92 [2] 9c 94 [2] 80 93 [2] 9c bc }

  condition:
    any of them
}