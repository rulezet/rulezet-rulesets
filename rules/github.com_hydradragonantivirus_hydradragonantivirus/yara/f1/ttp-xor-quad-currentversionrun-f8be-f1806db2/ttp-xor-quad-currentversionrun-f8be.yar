rule TTP_XOR_QUAD_CurrentVersionRun_f8be {
  strings:
    $key_f8be = { ab d1 [2] 8f df [2] a4 f3 [2] 8a d1 [2] 9e ca [2] 91 d0 [2] 8f cd [2] 8d cc [2] 96 ca [2] 8a cd [2] 96 e2 }

  condition:
    any of them
}