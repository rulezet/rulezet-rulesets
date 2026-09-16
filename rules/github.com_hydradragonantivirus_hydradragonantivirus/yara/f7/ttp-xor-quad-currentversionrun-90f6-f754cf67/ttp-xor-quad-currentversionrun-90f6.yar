rule TTP_XOR_QUAD_CurrentVersionRun_90f6 {
  strings:
    $key_90f6 = { c3 99 [2] e7 97 [2] cc bb [2] e2 99 [2] f6 82 [2] f9 98 [2] e7 85 [2] e5 84 [2] fe 82 [2] e2 85 [2] fe aa }

  condition:
    any of them
}