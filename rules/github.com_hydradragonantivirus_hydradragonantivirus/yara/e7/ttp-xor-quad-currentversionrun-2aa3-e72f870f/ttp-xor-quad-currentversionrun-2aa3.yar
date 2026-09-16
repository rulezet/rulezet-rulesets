rule TTP_XOR_QUAD_CurrentVersionRun_2aa3 {
  strings:
    $key_2aa3 = { 79 cc [2] 5d c2 [2] 76 ee [2] 58 cc [2] 4c d7 [2] 43 cd [2] 5d d0 [2] 5f d1 [2] 44 d7 [2] 58 d0 [2] 44 ff }

  condition:
    any of them
}