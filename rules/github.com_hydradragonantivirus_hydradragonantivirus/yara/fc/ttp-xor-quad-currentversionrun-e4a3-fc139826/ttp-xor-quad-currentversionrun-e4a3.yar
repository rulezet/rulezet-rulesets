rule TTP_XOR_QUAD_CurrentVersionRun_e4a3 {
  strings:
    $key_e4a3 = { b7 cc [2] 93 c2 [2] b8 ee [2] 96 cc [2] 82 d7 [2] 8d cd [2] 93 d0 [2] 91 d1 [2] 8a d7 [2] 96 d0 [2] 8a ff }

  condition:
    any of them
}