rule TTP_XOR_MULT_DOSStub_9d57 {
  strings:
    $key_9d57 = { c9 3f [2] bd 27 [2] fa 25 [2] bd 34 [2] f3 38 [2] ff 32 [2] e8 39 [2] f3 77 [2] ce }

  condition:
    any of them
}