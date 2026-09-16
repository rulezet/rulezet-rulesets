rule TTP_XOR_QUAD_CurrentVersionRun_bea3 {
  strings:
    $key_bea3 = { ed cc [2] c9 c2 [2] e2 ee [2] cc cc [2] d8 d7 [2] d7 cd [2] c9 d0 [2] cb d1 [2] d0 d7 [2] cc d0 [2] d0 ff }

  condition:
    any of them
}