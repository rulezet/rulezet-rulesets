rule TTP_XOR_QUAD_CurrentVersionRun_2fa3 {
  strings:
    $key_2fa3 = { 7c cc [2] 58 c2 [2] 73 ee [2] 5d cc [2] 49 d7 [2] 46 cd [2] 58 d0 [2] 5a d1 [2] 41 d7 [2] 5d d0 [2] 41 ff }

  condition:
    any of them
}