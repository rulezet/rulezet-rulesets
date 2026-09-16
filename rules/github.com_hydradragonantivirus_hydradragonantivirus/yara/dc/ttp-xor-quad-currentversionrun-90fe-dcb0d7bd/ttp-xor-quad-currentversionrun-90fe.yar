rule TTP_XOR_QUAD_CurrentVersionRun_90fe {
  strings:
    $key_90fe = { c3 91 [2] e7 9f [2] cc b3 [2] e2 91 [2] f6 8a [2] f9 90 [2] e7 8d [2] e5 8c [2] fe 8a [2] e2 8d [2] fe a2 }

  condition:
    any of them
}