rule TTP_XOR_QUAD_CurrentVersionRun_aaa3 {
  strings:
    $key_aaa3 = { f9 cc [2] dd c2 [2] f6 ee [2] d8 cc [2] cc d7 [2] c3 cd [2] dd d0 [2] df d1 [2] c4 d7 [2] d8 d0 [2] c4 ff }

  condition:
    any of them
}