rule TTP_XOR_QUAD_CurrentVersionRun_6ea3 {
  strings:
    $key_6ea3 = { 3d cc [2] 19 c2 [2] 32 ee [2] 1c cc [2] 08 d7 [2] 07 cd [2] 19 d0 [2] 1b d1 [2] 00 d7 [2] 1c d0 [2] 00 ff }

  condition:
    any of them
}