rule TTP_XOR_MULT_DOSStub_9dde {
  strings:
    $key_9dde = { c9 b6 [2] bd ae [2] fa ac [2] bd bd [2] f3 b1 [2] ff bb [2] e8 b0 [2] f3 fe [2] ce }

  condition:
    any of them
}