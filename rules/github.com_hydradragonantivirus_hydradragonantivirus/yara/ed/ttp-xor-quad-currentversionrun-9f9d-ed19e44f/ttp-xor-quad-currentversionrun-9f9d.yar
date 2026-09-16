rule TTP_XOR_QUAD_CurrentVersionRun_9f9d {
  strings:
    $key_9f9d = { cc f2 [2] e8 fc [2] c3 d0 [2] ed f2 [2] f9 e9 [2] f6 f3 [2] e8 ee [2] ea ef [2] f1 e9 [2] ed ee [2] f1 c1 }

  condition:
    any of them
}