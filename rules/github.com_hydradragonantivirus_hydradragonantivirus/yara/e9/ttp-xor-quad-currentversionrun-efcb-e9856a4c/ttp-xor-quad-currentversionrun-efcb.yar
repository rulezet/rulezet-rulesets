rule TTP_XOR_QUAD_CurrentVersionRun_efcb {
  strings:
    $key_efcb = { bc a4 [2] 98 aa [2] b3 86 [2] 9d a4 [2] 89 bf [2] 86 a5 [2] 98 b8 [2] 9a b9 [2] 81 bf [2] 9d b8 [2] 81 97 }

  condition:
    any of them
}