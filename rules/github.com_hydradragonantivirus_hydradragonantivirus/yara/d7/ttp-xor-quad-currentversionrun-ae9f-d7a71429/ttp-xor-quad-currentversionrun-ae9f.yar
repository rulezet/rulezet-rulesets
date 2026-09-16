rule TTP_XOR_QUAD_CurrentVersionRun_ae9f {
  strings:
    $key_ae9f = { fd f0 [2] d9 fe [2] f2 d2 [2] dc f0 [2] c8 eb [2] c7 f1 [2] d9 ec [2] db ed [2] c0 eb [2] dc ec [2] c0 c3 }

  condition:
    any of them
}