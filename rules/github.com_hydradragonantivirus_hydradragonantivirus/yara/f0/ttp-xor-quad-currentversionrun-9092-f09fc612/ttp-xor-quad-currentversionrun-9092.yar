rule TTP_XOR_QUAD_CurrentVersionRun_9092 {
  strings:
    $key_9092 = { c3 fd [2] e7 f3 [2] cc df [2] e2 fd [2] f6 e6 [2] f9 fc [2] e7 e1 [2] e5 e0 [2] fe e6 [2] e2 e1 [2] fe ce }

  condition:
    any of them
}