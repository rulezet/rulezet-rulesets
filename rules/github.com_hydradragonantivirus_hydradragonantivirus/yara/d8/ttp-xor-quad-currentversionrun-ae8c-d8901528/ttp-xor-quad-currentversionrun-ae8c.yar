rule TTP_XOR_QUAD_CurrentVersionRun_ae8c {
  strings:
    $key_ae8c = { fd e3 [2] d9 ed [2] f2 c1 [2] dc e3 [2] c8 f8 [2] c7 e2 [2] d9 ff [2] db fe [2] c0 f8 [2] dc ff [2] c0 d0 }

  condition:
    any of them
}