rule TTP_XOR_MULT_DOSStub_9d81 {
  strings:
    $key_9d81 = { c9 e9 [2] bd f1 [2] fa f3 [2] bd e2 [2] f3 ee [2] ff e4 [2] e8 ef [2] f3 a1 [2] ce }

  condition:
    any of them
}