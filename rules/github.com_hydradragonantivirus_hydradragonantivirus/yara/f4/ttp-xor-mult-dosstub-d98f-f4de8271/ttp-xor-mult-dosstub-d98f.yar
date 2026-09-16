rule TTP_XOR_MULT_DOSStub_d98f {
  strings:
    $key_d98f = { 8d e7 [2] f9 ff [2] be fd [2] f9 ec [2] b7 e0 [2] bb ea [2] ac e1 [2] b7 af [2] 8a }

  condition:
    any of them
}