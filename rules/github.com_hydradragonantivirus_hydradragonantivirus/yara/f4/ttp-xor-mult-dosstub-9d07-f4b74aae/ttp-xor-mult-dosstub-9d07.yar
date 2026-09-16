rule TTP_XOR_MULT_DOSStub_9d07 {
  strings:
    $key_9d07 = { c9 6f [2] bd 77 [2] fa 75 [2] bd 64 [2] f3 68 [2] ff 62 [2] e8 69 [2] f3 27 [2] ce }

  condition:
    any of them
}