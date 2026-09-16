rule TTP_XOR_QUAD_CurrentVersionRun_eff2 {
  strings:
    $key_eff2 = { bc 9d [2] 98 93 [2] b3 bf [2] 9d 9d [2] 89 86 [2] 86 9c [2] 98 81 [2] 9a 80 [2] 81 86 [2] 9d 81 [2] 81 ae }

  condition:
    any of them
}