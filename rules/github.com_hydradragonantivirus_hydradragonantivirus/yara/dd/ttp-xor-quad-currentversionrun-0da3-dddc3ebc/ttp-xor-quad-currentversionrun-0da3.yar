rule TTP_XOR_QUAD_CurrentVersionRun_0da3 {
  strings:
    $key_0da3 = { 5e cc [2] 7a c2 [2] 51 ee [2] 7f cc [2] 6b d7 [2] 64 cd [2] 7a d0 [2] 78 d1 [2] 63 d7 [2] 7f d0 [2] 63 ff }

  condition:
    any of them
}