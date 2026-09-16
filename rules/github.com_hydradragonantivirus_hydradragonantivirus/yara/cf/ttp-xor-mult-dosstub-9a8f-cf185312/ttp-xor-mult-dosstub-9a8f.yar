rule TTP_XOR_MULT_DOSStub_9a8f {
  strings:
    $key_9a8f = { ce e7 [2] ba ff [2] fd fd [2] ba ec [2] f4 e0 [2] f8 ea [2] ef e1 [2] f4 af [2] c9 }

  condition:
    any of them
}