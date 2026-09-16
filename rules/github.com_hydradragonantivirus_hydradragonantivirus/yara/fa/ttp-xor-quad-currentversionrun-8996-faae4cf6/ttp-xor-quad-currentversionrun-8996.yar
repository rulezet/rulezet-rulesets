rule TTP_XOR_QUAD_CurrentVersionRun_8996 {
  strings:
    $key_8996 = { da f9 [2] fe f7 [2] d5 db [2] fb f9 [2] ef e2 [2] e0 f8 [2] fe e5 [2] fc e4 [2] e7 e2 [2] fb e5 [2] e7 ca }

  condition:
    any of them
}