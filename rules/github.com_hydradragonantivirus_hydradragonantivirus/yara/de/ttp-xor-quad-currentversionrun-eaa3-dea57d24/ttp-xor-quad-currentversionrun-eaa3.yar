rule TTP_XOR_QUAD_CurrentVersionRun_eaa3 {
  strings:
    $key_eaa3 = { b9 cc [2] 9d c2 [2] b6 ee [2] 98 cc [2] 8c d7 [2] 83 cd [2] 9d d0 [2] 9f d1 [2] 84 d7 [2] 98 d0 [2] 84 ff }

  condition:
    any of them
}