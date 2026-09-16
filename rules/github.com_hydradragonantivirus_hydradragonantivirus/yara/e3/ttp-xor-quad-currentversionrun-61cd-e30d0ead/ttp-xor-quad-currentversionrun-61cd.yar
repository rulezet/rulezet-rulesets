rule TTP_XOR_QUAD_CurrentVersionRun_61cd {
  strings:
    $key_61cd = { 32 a2 [2] 16 ac [2] 3d 80 [2] 13 a2 [2] 07 b9 [2] 08 a3 [2] 16 be [2] 14 bf [2] 0f b9 [2] 13 be [2] 0f 91 }

  condition:
    any of them
}