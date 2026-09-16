rule TTP_XOR_QUAD_CurrentVersionRun_fdbe {
  strings:
    $key_fdbe = { ae d1 [2] 8a df [2] a1 f3 [2] 8f d1 [2] 9b ca [2] 94 d0 [2] 8a cd [2] 88 cc [2] 93 ca [2] 8f cd [2] 93 e2 }

  condition:
    any of them
}