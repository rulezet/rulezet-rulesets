rule TTP_XOR_QUAD_CurrentVersionRun_efb1 {
  strings:
    $key_efb1 = { bc de [2] 98 d0 [2] b3 fc [2] 9d de [2] 89 c5 [2] 86 df [2] 98 c2 [2] 9a c3 [2] 81 c5 [2] 9d c2 [2] 81 ed }

  condition:
    any of them
}