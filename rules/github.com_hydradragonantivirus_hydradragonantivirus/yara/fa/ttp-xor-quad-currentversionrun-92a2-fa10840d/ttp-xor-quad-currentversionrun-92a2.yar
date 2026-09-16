rule TTP_XOR_QUAD_CurrentVersionRun_92a2 {
  strings:
    $key_92a2 = { c1 cd [2] e5 c3 [2] ce ef [2] e0 cd [2] f4 d6 [2] fb cc [2] e5 d1 [2] e7 d0 [2] fc d6 [2] e0 d1 [2] fc fe }

  condition:
    any of them
}