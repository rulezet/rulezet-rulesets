rule TTP_XOR_QUAD_CurrentVersionRun_2dcd {
  strings:
    $key_2dcd = { 7e a2 [2] 5a ac [2] 71 80 [2] 5f a2 [2] 4b b9 [2] 44 a3 [2] 5a be [2] 58 bf [2] 43 b9 [2] 5f be [2] 43 91 }

  condition:
    any of them
}