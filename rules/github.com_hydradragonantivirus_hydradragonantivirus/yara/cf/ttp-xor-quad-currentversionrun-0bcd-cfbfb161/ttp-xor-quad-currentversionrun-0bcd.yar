rule TTP_XOR_QUAD_CurrentVersionRun_0bcd {
  strings:
    $key_0bcd = { 58 a2 [2] 7c ac [2] 57 80 [2] 79 a2 [2] 6d b9 [2] 62 a3 [2] 7c be [2] 7e bf [2] 65 b9 [2] 79 be [2] 65 91 }

  condition:
    any of them
}