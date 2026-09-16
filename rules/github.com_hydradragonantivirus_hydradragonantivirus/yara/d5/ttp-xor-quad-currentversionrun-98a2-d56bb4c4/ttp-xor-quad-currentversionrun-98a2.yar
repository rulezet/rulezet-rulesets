rule TTP_XOR_QUAD_CurrentVersionRun_98a2 {
  strings:
    $key_98a2 = { cb cd [2] ef c3 [2] c4 ef [2] ea cd [2] fe d6 [2] f1 cc [2] ef d1 [2] ed d0 [2] f6 d6 [2] ea d1 [2] f6 fe }

  condition:
    any of them
}