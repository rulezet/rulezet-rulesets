rule TTP_XOR_QUAD_CurrentVersionRun_7dcd {
  strings:
    $key_7dcd = { 2e a2 [2] 0a ac [2] 21 80 [2] 0f a2 [2] 1b b9 [2] 14 a3 [2] 0a be [2] 08 bf [2] 13 b9 [2] 0f be [2] 13 91 }

  condition:
    any of them
}