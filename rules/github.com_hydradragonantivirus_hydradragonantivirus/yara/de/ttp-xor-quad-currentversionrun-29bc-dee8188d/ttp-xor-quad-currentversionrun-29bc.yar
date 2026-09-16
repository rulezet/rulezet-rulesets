rule TTP_XOR_QUAD_CurrentVersionRun_29bc {
  strings:
    $key_29bc = { 7a d3 [2] 5e dd [2] 75 f1 [2] 5b d3 [2] 4f c8 [2] 40 d2 [2] 5e cf [2] 5c ce [2] 47 c8 [2] 5b cf [2] 47 e0 }

  condition:
    any of them
}