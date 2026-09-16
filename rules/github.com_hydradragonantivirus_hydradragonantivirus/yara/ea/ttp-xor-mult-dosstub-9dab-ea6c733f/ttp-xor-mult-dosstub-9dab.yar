rule TTP_XOR_MULT_DOSStub_9dab {
  strings:
    $key_9dab = { c9 c3 [2] bd db [2] fa d9 [2] bd c8 [2] f3 c4 [2] ff ce [2] e8 c5 [2] f3 8b [2] ce }

  condition:
    any of them
}