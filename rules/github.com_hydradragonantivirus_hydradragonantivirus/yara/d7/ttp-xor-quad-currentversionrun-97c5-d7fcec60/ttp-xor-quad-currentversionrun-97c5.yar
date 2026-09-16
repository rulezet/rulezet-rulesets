rule TTP_XOR_QUAD_CurrentVersionRun_97c5 {
  strings:
    $key_97c5 = { c4 aa [2] e0 a4 [2] cb 88 [2] e5 aa [2] f1 b1 [2] fe ab [2] e0 b6 [2] e2 b7 [2] f9 b1 [2] e5 b6 [2] f9 99 }

  condition:
    any of them
}