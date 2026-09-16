rule TTP_XOR_QUAD_CurrentVersionRun_3dcd {
  strings:
    $key_3dcd = { 6e a2 [2] 4a ac [2] 61 80 [2] 4f a2 [2] 5b b9 [2] 54 a3 [2] 4a be [2] 48 bf [2] 53 b9 [2] 4f be [2] 53 91 }

  condition:
    any of them
}