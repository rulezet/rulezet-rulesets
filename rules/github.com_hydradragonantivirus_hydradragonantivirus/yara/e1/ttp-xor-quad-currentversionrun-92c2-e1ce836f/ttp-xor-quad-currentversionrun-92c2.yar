rule TTP_XOR_QUAD_CurrentVersionRun_92c2 {
  strings:
    $key_92c2 = { c1 ad [2] e5 a3 [2] ce 8f [2] e0 ad [2] f4 b6 [2] fb ac [2] e5 b1 [2] e7 b0 [2] fc b6 [2] e0 b1 [2] fc 9e }

  condition:
    any of them
}