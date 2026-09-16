rule TTP_XOR_QUAD_CurrentVersionRun_04a3 {
  strings:
    $key_04a3 = { 57 cc [2] 73 c2 [2] 58 ee [2] 76 cc [2] 62 d7 [2] 6d cd [2] 73 d0 [2] 71 d1 [2] 6a d7 [2] 76 d0 [2] 6a ff }

  condition:
    any of them
}