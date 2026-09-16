rule TTP_XOR_QUAD_CurrentVersionRun_8bb8 {
  strings:
    $key_8bb8 = { d8 d7 [2] fc d9 [2] d7 f5 [2] f9 d7 [2] ed cc [2] e2 d6 [2] fc cb [2] fe ca [2] e5 cc [2] f9 cb [2] e5 e4 }

  condition:
    any of them
}