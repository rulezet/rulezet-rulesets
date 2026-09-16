rule TTP_XOR_QUAD_CurrentVersionRun_8e87 {
  strings:
    $key_8e87 = { dd e8 [2] f9 e6 [2] d2 ca [2] fc e8 [2] e8 f3 [2] e7 e9 [2] f9 f4 [2] fb f5 [2] e0 f3 [2] fc f4 [2] e0 db }

  condition:
    any of them
}