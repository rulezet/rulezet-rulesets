rule TTP_XOR_QUAD_CurrentVersionRun_abab {
  strings:
    $key_abab = { f8 c4 [2] dc ca [2] f7 e6 [2] d9 c4 [2] cd df [2] c2 c5 [2] dc d8 [2] de d9 [2] c5 df [2] d9 d8 [2] c5 f7 }

  condition:
    any of them
}