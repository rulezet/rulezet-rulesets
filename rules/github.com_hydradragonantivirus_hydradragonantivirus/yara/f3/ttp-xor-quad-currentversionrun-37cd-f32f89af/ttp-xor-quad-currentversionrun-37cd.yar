rule TTP_XOR_QUAD_CurrentVersionRun_37cd {
  strings:
    $key_37cd = { 64 a2 [2] 40 ac [2] 6b 80 [2] 45 a2 [2] 51 b9 [2] 5e a3 [2] 40 be [2] 42 bf [2] 59 b9 [2] 45 be [2] 59 91 }

  condition:
    any of them
}