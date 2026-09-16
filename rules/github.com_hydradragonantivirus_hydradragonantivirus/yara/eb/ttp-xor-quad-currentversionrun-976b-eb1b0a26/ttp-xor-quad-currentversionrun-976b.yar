rule TTP_XOR_QUAD_CurrentVersionRun_976b {
  strings:
    $key_976b = { c4 04 [2] e0 0a [2] cb 26 [2] e5 04 [2] f1 1f [2] fe 05 [2] e0 18 [2] e2 19 [2] f9 1f [2] e5 18 [2] f9 37 }

  condition:
    any of them
}