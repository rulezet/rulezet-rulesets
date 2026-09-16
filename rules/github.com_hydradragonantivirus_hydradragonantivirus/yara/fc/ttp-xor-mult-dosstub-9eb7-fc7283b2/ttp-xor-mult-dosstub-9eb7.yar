rule TTP_XOR_MULT_DOSStub_9eb7 {
  strings:
    $key_9eb7 = { ca df [2] be c7 [2] f9 c5 [2] be d4 [2] f0 d8 [2] fc d2 [2] eb d9 [2] f0 97 [2] cd }

  condition:
    any of them
}