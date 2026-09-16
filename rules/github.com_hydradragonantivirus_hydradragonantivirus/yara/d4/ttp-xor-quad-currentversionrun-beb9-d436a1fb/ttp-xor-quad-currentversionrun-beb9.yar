rule TTP_XOR_QUAD_CurrentVersionRun_beb9 {
  strings:
    $key_beb9 = { ed d6 [2] c9 d8 [2] e2 f4 [2] cc d6 [2] d8 cd [2] d7 d7 [2] c9 ca [2] cb cb [2] d0 cd [2] cc ca [2] d0 e5 }

  condition:
    any of them
}