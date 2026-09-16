rule TTP_XOR_MULT_DOSStub_9dc9 {
  strings:
    $key_9dc9 = { c9 a1 [2] bd b9 [2] fa bb [2] bd aa [2] f3 a6 [2] ff ac [2] e8 a7 [2] f3 e9 [2] ce }

  condition:
    any of them
}