rule TTP_XOR_MULT_DOSStub_9dd8 {
  strings:
    $key_9dd8 = { c9 b0 [2] bd a8 [2] fa aa [2] bd bb [2] f3 b7 [2] ff bd [2] e8 b6 [2] f3 f8 [2] ce }

  condition:
    any of them
}