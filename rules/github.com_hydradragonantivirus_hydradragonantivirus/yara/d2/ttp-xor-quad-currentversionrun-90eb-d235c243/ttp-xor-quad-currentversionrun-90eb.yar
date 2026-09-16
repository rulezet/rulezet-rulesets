rule TTP_XOR_QUAD_CurrentVersionRun_90eb {
  strings:
    $key_90eb = { c3 84 [2] e7 8a [2] cc a6 [2] e2 84 [2] f6 9f [2] f9 85 [2] e7 98 [2] e5 99 [2] fe 9f [2] e2 98 [2] fe b7 }

  condition:
    any of them
}