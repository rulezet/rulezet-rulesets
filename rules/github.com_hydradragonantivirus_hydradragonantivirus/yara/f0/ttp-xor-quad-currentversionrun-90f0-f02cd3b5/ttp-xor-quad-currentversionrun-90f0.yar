rule TTP_XOR_QUAD_CurrentVersionRun_90f0 {
  strings:
    $key_90f0 = { c3 9f [2] e7 91 [2] cc bd [2] e2 9f [2] f6 84 [2] f9 9e [2] e7 83 [2] e5 82 [2] fe 84 [2] e2 83 [2] fe ac }

  condition:
    any of them
}