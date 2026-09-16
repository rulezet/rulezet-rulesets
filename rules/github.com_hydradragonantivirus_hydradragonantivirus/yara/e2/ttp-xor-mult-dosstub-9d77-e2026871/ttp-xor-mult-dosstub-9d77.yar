rule TTP_XOR_MULT_DOSStub_9d77 {
  strings:
    $key_9d77 = { c9 1f [2] bd 07 [2] fa 05 [2] bd 14 [2] f3 18 [2] ff 12 [2] e8 19 [2] f3 57 [2] ce }

  condition:
    any of them
}