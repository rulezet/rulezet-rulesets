rule TTP_XOR_MULT_DOSStub_9da7 {
  strings:
    $key_9da7 = { c9 cf [2] bd d7 [2] fa d5 [2] bd c4 [2] f3 c8 [2] ff c2 [2] e8 c9 [2] f3 87 [2] ce }

  condition:
    any of them
}