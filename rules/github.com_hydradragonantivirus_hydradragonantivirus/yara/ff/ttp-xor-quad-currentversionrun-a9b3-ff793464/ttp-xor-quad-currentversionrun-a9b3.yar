rule TTP_XOR_QUAD_CurrentVersionRun_a9b3 {
  strings:
    $key_a9b3 = { fa dc [2] de d2 [2] f5 fe [2] db dc [2] cf c7 [2] c0 dd [2] de c0 [2] dc c1 [2] c7 c7 [2] db c0 [2] c7 ef }

  condition:
    any of them
}