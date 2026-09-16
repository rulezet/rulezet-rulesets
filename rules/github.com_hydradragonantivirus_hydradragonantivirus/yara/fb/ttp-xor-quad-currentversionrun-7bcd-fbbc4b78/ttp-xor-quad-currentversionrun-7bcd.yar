rule TTP_XOR_QUAD_CurrentVersionRun_7bcd {
  strings:
    $key_7bcd = { 28 a2 [2] 0c ac [2] 27 80 [2] 09 a2 [2] 1d b9 [2] 12 a3 [2] 0c be [2] 0e bf [2] 15 b9 [2] 09 be [2] 15 91 }

  condition:
    any of them
}