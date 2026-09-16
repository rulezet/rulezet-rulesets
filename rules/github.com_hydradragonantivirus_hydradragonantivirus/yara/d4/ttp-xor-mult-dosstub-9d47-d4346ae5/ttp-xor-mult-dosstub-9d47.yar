rule TTP_XOR_MULT_DOSStub_9d47 {
  strings:
    $key_9d47 = { c9 2f [2] bd 37 [2] fa 35 [2] bd 24 [2] f3 28 [2] ff 22 [2] e8 29 [2] f3 67 [2] ce }

  condition:
    any of them
}