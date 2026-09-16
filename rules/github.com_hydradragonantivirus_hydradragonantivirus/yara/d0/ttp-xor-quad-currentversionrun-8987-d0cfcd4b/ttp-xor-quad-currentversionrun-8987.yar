rule TTP_XOR_QUAD_CurrentVersionRun_8987 {
  strings:
    $key_8987 = { da e8 [2] fe e6 [2] d5 ca [2] fb e8 [2] ef f3 [2] e0 e9 [2] fe f4 [2] fc f5 [2] e7 f3 [2] fb f4 [2] e7 db }

  condition:
    any of them
}