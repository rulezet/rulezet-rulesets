rule TTP_XOR_MULT_DOSStub_9da4 {
  strings:
    $key_9da4 = { c9 cc [2] bd d4 [2] fa d6 [2] bd c7 [2] f3 cb [2] ff c1 [2] e8 ca [2] f3 84 [2] ce }

  condition:
    any of them
}