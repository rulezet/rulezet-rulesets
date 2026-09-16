rule TTP_XOR_QUAD_CurrentVersionRun_619e {
  strings:
    $key_619e = { 32 f1 [2] 16 ff [2] 3d d3 [2] 13 f1 [2] 07 ea [2] 08 f0 [2] 16 ed [2] 14 ec [2] 0f ea [2] 13 ed [2] 0f c2 }

  condition:
    any of them
}