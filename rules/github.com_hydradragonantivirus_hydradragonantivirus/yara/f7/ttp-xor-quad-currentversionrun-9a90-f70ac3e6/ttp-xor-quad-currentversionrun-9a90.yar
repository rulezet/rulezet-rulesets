rule TTP_XOR_QUAD_CurrentVersionRun_9a90 {
  strings:
    $key_9a90 = { c9 ff [2] ed f1 [2] c6 dd [2] e8 ff [2] fc e4 [2] f3 fe [2] ed e3 [2] ef e2 [2] f4 e4 [2] e8 e3 [2] f4 cc }

  condition:
    any of them
}