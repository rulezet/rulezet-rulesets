rule TTP_XOR_QUAD_CurrentVersionRun_81cd {
  strings:
    $key_81cd = { d2 a2 [2] f6 ac [2] dd 80 [2] f3 a2 [2] e7 b9 [2] e8 a3 [2] f6 be [2] f4 bf [2] ef b9 [2] f3 be [2] ef 91 }

  condition:
    any of them
}