rule TTP_XOR_QUAD_CurrentVersionRun_903b {
  strings:
    $key_903b = { c3 54 [2] e7 5a [2] cc 76 [2] e2 54 [2] f6 4f [2] f9 55 [2] e7 48 [2] e5 49 [2] fe 4f [2] e2 48 [2] fe 67 }

  condition:
    any of them
}