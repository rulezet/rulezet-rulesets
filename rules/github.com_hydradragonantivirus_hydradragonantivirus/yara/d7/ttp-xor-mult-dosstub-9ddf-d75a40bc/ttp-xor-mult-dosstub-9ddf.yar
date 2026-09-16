rule TTP_XOR_MULT_DOSStub_9ddf {
  strings:
    $key_9ddf = { c9 b7 [2] bd af [2] fa ad [2] bd bc [2] f3 b0 [2] ff ba [2] e8 b1 [2] f3 ff [2] ce }

  condition:
    any of them
}