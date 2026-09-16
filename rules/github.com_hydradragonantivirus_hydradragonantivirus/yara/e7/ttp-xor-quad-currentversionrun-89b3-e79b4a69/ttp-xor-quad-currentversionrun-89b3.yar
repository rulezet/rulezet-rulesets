rule TTP_XOR_QUAD_CurrentVersionRun_89b3 {
  strings:
    $key_89b3 = { da dc [2] fe d2 [2] d5 fe [2] fb dc [2] ef c7 [2] e0 dd [2] fe c0 [2] fc c1 [2] e7 c7 [2] fb c0 [2] e7 ef }

  condition:
    any of them
}