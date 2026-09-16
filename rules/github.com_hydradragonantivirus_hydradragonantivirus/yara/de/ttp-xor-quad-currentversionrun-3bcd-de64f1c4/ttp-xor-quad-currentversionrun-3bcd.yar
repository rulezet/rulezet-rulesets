rule TTP_XOR_QUAD_CurrentVersionRun_3bcd {
  strings:
    $key_3bcd = { 68 a2 [2] 4c ac [2] 67 80 [2] 49 a2 [2] 5d b9 [2] 52 a3 [2] 4c be [2] 4e bf [2] 55 b9 [2] 49 be [2] 55 91 }

  condition:
    any of them
}