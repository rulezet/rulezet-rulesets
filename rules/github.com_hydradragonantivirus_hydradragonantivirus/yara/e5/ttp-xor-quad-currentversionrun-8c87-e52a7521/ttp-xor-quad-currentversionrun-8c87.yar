rule TTP_XOR_QUAD_CurrentVersionRun_8c87 {
  strings:
    $key_8c87 = { df e8 [2] fb e6 [2] d0 ca [2] fe e8 [2] ea f3 [2] e5 e9 [2] fb f4 [2] f9 f5 [2] e2 f3 [2] fe f4 [2] e2 db }

  condition:
    any of them
}