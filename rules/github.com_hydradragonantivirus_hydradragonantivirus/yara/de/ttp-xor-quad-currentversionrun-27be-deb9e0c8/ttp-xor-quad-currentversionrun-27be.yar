rule TTP_XOR_QUAD_CurrentVersionRun_27be {
  strings:
    $key_27be = { 74 d1 [2] 50 df [2] 7b f3 [2] 55 d1 [2] 41 ca [2] 4e d0 [2] 50 cd [2] 52 cc [2] 49 ca [2] 55 cd [2] 49 e2 }

  condition:
    any of them
}