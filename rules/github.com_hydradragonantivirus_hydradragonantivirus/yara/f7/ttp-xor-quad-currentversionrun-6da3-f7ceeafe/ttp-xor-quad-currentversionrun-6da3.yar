rule TTP_XOR_QUAD_CurrentVersionRun_6da3 {
  strings:
    $key_6da3 = { 3e cc [2] 1a c2 [2] 31 ee [2] 1f cc [2] 0b d7 [2] 04 cd [2] 1a d0 [2] 18 d1 [2] 03 d7 [2] 1f d0 [2] 03 ff }

  condition:
    any of them
}