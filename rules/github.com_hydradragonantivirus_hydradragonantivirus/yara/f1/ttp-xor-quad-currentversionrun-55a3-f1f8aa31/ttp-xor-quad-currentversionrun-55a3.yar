rule TTP_XOR_QUAD_CurrentVersionRun_55a3 {
  strings:
    $key_55a3 = { 06 cc [2] 22 c2 [2] 09 ee [2] 27 cc [2] 33 d7 [2] 3c cd [2] 22 d0 [2] 20 d1 [2] 3b d7 [2] 27 d0 [2] 3b ff }

  condition:
    any of them
}