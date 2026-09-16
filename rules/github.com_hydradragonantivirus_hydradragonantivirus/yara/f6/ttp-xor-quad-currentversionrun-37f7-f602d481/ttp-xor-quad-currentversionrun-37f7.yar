rule TTP_XOR_QUAD_CurrentVersionRun_37f7 {
  strings:
    $key_37f7 = { 64 98 [2] 40 96 [2] 6b ba [2] 45 98 [2] 51 83 [2] 5e 99 [2] 40 84 [2] 42 85 [2] 59 83 [2] 45 84 [2] 59 ab }

  condition:
    any of them
}