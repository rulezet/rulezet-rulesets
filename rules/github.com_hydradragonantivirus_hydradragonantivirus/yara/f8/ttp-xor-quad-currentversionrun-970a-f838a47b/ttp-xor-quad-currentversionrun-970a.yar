rule TTP_XOR_QUAD_CurrentVersionRun_970a {
  strings:
    $key_970a = { c4 65 [2] e0 6b [2] cb 47 [2] e5 65 [2] f1 7e [2] fe 64 [2] e0 79 [2] e2 78 [2] f9 7e [2] e5 79 [2] f9 56 }

  condition:
    any of them
}