rule TTP_XOR_QUAD_CurrentVersionRun_16f3 {
  strings:
    $key_16f3 = { 45 9c [2] 61 92 [2] 4a be [2] 64 9c [2] 70 87 [2] 7f 9d [2] 61 80 [2] 63 81 [2] 78 87 [2] 64 80 [2] 78 af }

  condition:
    any of them
}