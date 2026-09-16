rule TTP_XOR_QUAD_CurrentVersionRun_9dbe {
  strings:
    $key_9dbe = { ce d1 [2] ea df [2] c1 f3 [2] ef d1 [2] fb ca [2] f4 d0 [2] ea cd [2] e8 cc [2] f3 ca [2] ef cd [2] f3 e2 }

  condition:
    any of them
}