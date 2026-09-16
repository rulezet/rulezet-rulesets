rule TTP_XOR_QUAD_CurrentVersionRun_1613 {
  strings:
    $key_1613 = { 45 7c [2] 61 72 [2] 4a 5e [2] 64 7c [2] 70 67 [2] 7f 7d [2] 61 60 [2] 63 61 [2] 78 67 [2] 64 60 [2] 78 4f }

  condition:
    any of them
}