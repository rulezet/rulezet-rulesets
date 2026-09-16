rule TTP_XOR_QUAD_CurrentVersionRun_ccab {
  strings:
    $key_ccab = { 9f c4 [2] bb ca [2] 90 e6 [2] be c4 [2] aa df [2] a5 c5 [2] bb d8 [2] b9 d9 [2] a2 df [2] be d8 [2] a2 f7 }

  condition:
    any of them
}