rule TTP_XOR_QUAD_CurrentVersionRun_efab {
  strings:
    $key_efab = { bc c4 [2] 98 ca [2] b3 e6 [2] 9d c4 [2] 89 df [2] 86 c5 [2] 98 d8 [2] 9a d9 [2] 81 df [2] 9d d8 [2] 81 f7 }

  condition:
    any of them
}