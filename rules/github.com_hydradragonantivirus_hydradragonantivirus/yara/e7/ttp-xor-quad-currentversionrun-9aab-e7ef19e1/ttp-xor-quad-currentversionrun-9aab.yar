rule TTP_XOR_QUAD_CurrentVersionRun_9aab {
  strings:
    $key_9aab = { c9 c4 [2] ed ca [2] c6 e6 [2] e8 c4 [2] fc df [2] f3 c5 [2] ed d8 [2] ef d9 [2] f4 df [2] e8 d8 [2] f4 f7 }

  condition:
    any of them
}