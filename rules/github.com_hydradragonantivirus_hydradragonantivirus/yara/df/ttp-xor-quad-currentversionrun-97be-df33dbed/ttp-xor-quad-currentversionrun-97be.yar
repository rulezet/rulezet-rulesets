rule TTP_XOR_QUAD_CurrentVersionRun_97be {
  strings:
    $key_97be = { c4 d1 [2] e0 df [2] cb f3 [2] e5 d1 [2] f1 ca [2] fe d0 [2] e0 cd [2] e2 cc [2] f9 ca [2] e5 cd [2] f9 e2 }

  condition:
    any of them
}