rule TTP_XOR_QUAD_CurrentVersionRun_2da3 {
  strings:
    $key_2da3 = { 7e cc [2] 5a c2 [2] 71 ee [2] 5f cc [2] 4b d7 [2] 44 cd [2] 5a d0 [2] 58 d1 [2] 43 d7 [2] 5f d0 [2] 43 ff }

  condition:
    any of them
}