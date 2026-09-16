rule TTP_XOR_QUAD_CurrentVersionRun_a9a2 {
  strings:
    $key_a9a2 = { fa cd [2] de c3 [2] f5 ef [2] db cd [2] cf d6 [2] c0 cc [2] de d1 [2] dc d0 [2] c7 d6 [2] db d1 [2] c7 fe }

  condition:
    any of them
}