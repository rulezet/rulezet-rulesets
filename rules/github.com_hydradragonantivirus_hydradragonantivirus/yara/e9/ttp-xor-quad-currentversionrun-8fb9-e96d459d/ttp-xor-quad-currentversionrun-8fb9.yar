rule TTP_XOR_QUAD_CurrentVersionRun_8fb9 {
  strings:
    $key_8fb9 = { dc d6 [2] f8 d8 [2] d3 f4 [2] fd d6 [2] e9 cd [2] e6 d7 [2] f8 ca [2] fa cb [2] e1 cd [2] fd ca [2] e1 e5 }

  condition:
    any of them
}