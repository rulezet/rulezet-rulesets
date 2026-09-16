rule TTP_XOR_QUAD_CurrentVersionRun_cdcd {
  strings:
    $key_cdcd = { 9e a2 [2] ba ac [2] 91 80 [2] bf a2 [2] ab b9 [2] a4 a3 [2] ba be [2] b8 bf [2] a3 b9 [2] bf be [2] a3 91 }

  condition:
    any of them
}