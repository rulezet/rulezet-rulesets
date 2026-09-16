rule TTP_XOR_QUAD_CurrentVersionRun_ae91 {
  strings:
    $key_ae91 = { fd fe [2] d9 f0 [2] f2 dc [2] dc fe [2] c8 e5 [2] c7 ff [2] d9 e2 [2] db e3 [2] c0 e5 [2] dc e2 [2] c0 cd }

  condition:
    any of them
}