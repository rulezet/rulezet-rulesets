rule TTP_XOR_QUAD_CurrentVersionRun_02cd {
  strings:
    $key_02cd = { 51 a2 [2] 75 ac [2] 5e 80 [2] 70 a2 [2] 64 b9 [2] 6b a3 [2] 75 be [2] 77 bf [2] 6c b9 [2] 70 be [2] 6c 91 }

  condition:
    any of them
}