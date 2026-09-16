rule TTP_XOR_MULT_DOSStub_9dba {
  strings:
    $key_9dba = { c9 d2 [2] bd ca [2] fa c8 [2] bd d9 [2] f3 d5 [2] ff df [2] e8 d4 [2] f3 9a [2] ce }

  condition:
    any of them
}