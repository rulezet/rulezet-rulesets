rule TTP_XOR_MULT_DOSStub_9d8d {
  strings:
    $key_9d8d = { c9 e5 [2] bd fd [2] fa ff [2] bd ee [2] f3 e2 [2] ff e8 [2] e8 e3 [2] f3 ad [2] ce }

  condition:
    any of them
}