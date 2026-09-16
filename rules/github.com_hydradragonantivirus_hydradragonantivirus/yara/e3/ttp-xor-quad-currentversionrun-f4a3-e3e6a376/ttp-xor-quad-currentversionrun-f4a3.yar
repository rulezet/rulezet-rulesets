rule TTP_XOR_QUAD_CurrentVersionRun_f4a3 {
  strings:
    $key_f4a3 = { a7 cc [2] 83 c2 [2] a8 ee [2] 86 cc [2] 92 d7 [2] 9d cd [2] 83 d0 [2] 81 d1 [2] 9a d7 [2] 86 d0 [2] 9a ff }

  condition:
    any of them
}