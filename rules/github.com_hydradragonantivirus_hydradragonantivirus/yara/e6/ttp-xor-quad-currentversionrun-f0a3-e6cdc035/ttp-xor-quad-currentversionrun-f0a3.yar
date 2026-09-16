rule TTP_XOR_QUAD_CurrentVersionRun_f0a3 {
  strings:
    $key_f0a3 = { a3 cc [2] 87 c2 [2] ac ee [2] 82 cc [2] 96 d7 [2] 99 cd [2] 87 d0 [2] 85 d1 [2] 9e d7 [2] 82 d0 [2] 9e ff }

  condition:
    any of them
}