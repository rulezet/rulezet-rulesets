rule TTP_XOR_QUAD_CurrentVersionRun_a5a6 {
  strings:
    $key_a5a6 = { f6 c9 [2] d2 c7 [2] f9 eb [2] d7 c9 [2] c3 d2 [2] cc c8 [2] d2 d5 [2] d0 d4 [2] cb d2 [2] d7 d5 [2] cb fa }

  condition:
    any of them
}