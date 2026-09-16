rule TTP_XOR_QUAD_CurrentVersionRun_3aab {
  strings:
    $key_3aab = { 69 c4 [2] 4d ca [2] 66 e6 [2] 48 c4 [2] 5c df [2] 53 c5 [2] 4d d8 [2] 4f d9 [2] 54 df [2] 48 d8 [2] 54 f7 }

  condition:
    any of them
}