rule TTP_XOR_MULT_DOSStub_9dc7 {
  strings:
    $key_9dc7 = { c9 af [2] bd b7 [2] fa b5 [2] bd a4 [2] f3 a8 [2] ff a2 [2] e8 a9 [2] f3 e7 [2] ce }

  condition:
    any of them
}