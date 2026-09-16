rule TTP_XOR_QUAD_CurrentVersionRun_3aa8 {
  strings:
    $key_3aa8 = { 69 c7 [2] 4d c9 [2] 66 e5 [2] 48 c7 [2] 5c dc [2] 53 c6 [2] 4d db [2] 4f da [2] 54 dc [2] 48 db [2] 54 f4 }

  condition:
    any of them
}