rule TTP_XOR_QUAD_CurrentVersionRun_48be {
  strings:
    $key_48be = { 1b d1 [2] 3f df [2] 14 f3 [2] 3a d1 [2] 2e ca [2] 21 d0 [2] 3f cd [2] 3d cc [2] 26 ca [2] 3a cd [2] 26 e2 }

  condition:
    any of them
}