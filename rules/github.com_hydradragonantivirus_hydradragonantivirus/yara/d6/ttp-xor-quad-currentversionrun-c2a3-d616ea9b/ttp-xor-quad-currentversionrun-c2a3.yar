rule TTP_XOR_QUAD_CurrentVersionRun_c2a3 {
  strings:
    $key_c2a3 = { 91 cc [2] b5 c2 [2] 9e ee [2] b0 cc [2] a4 d7 [2] ab cd [2] b5 d0 [2] b7 d1 [2] ac d7 [2] b0 d0 [2] ac ff }

  condition:
    any of them
}