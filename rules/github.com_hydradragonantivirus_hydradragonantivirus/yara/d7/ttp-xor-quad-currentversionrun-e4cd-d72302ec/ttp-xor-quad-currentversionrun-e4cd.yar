rule TTP_XOR_QUAD_CurrentVersionRun_e4cd {
  strings:
    $key_e4cd = { b7 a2 [2] 93 ac [2] b8 80 [2] 96 a2 [2] 82 b9 [2] 8d a3 [2] 93 be [2] 91 bf [2] 8a b9 [2] 96 be [2] 8a 91 }

  condition:
    any of them
}