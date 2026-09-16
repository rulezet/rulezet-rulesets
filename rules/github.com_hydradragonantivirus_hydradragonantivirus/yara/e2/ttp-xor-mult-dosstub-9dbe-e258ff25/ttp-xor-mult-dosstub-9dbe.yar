rule TTP_XOR_MULT_DOSStub_9dbe {
  strings:
    $key_9dbe = { c9 d6 [2] bd ce [2] fa cc [2] bd dd [2] f3 d1 [2] ff db [2] e8 d0 [2] f3 9e [2] ce }

  condition:
    any of them
}