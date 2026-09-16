rule TTP_XOR_QUAD_CurrentVersionRun_9892 {
  strings:
    $key_9892 = { cb fd [2] ef f3 [2] c4 df [2] ea fd [2] fe e6 [2] f1 fc [2] ef e1 [2] ed e0 [2] f6 e6 [2] ea e1 [2] f6 ce }

  condition:
    any of them
}