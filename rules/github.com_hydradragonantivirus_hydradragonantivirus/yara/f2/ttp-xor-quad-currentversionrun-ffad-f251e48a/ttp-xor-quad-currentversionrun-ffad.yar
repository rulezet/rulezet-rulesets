rule TTP_XOR_QUAD_CurrentVersionRun_ffad {
  strings:
    $key_ffad = { ac c2 [2] 88 cc [2] a3 e0 [2] 8d c2 [2] 99 d9 [2] 96 c3 [2] 88 de [2] 8a df [2] 91 d9 [2] 8d de [2] 91 f1 }

  condition:
    any of them
}