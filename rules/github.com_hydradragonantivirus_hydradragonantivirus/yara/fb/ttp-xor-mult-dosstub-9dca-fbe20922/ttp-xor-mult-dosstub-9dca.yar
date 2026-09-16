rule TTP_XOR_MULT_DOSStub_9dca {
  strings:
    $key_9dca = { c9 a2 [2] bd ba [2] fa b8 [2] bd a9 [2] f3 a5 [2] ff af [2] e8 a4 [2] f3 ea [2] ce }

  condition:
    any of them
}