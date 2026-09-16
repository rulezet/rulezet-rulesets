rule TTP_XOR_MULT_DOSStub_9d8c {
  strings:
    $key_9d8c = { c9 e4 [2] bd fc [2] fa fe [2] bd ef [2] f3 e3 [2] ff e9 [2] e8 e2 [2] f3 ac [2] ce }

  condition:
    any of them
}