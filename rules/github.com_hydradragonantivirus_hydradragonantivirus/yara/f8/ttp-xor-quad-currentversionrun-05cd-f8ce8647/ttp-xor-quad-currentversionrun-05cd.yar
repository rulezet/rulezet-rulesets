rule TTP_XOR_QUAD_CurrentVersionRun_05cd {
  strings:
    $key_05cd = { 56 a2 [2] 72 ac [2] 59 80 [2] 77 a2 [2] 63 b9 [2] 6c a3 [2] 72 be [2] 70 bf [2] 6b b9 [2] 77 be [2] 6b 91 }

  condition:
    any of them
}