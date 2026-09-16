rule TTP_XOR_QUAD_CurrentVersionRun_dea3 {
  strings:
    $key_dea3 = { 8d cc [2] a9 c2 [2] 82 ee [2] ac cc [2] b8 d7 [2] b7 cd [2] a9 d0 [2] ab d1 [2] b0 d7 [2] ac d0 [2] b0 ff }

  condition:
    any of them
}