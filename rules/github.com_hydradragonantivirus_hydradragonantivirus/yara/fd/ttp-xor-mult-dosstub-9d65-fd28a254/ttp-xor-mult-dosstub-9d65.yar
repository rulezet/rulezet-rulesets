rule TTP_XOR_MULT_DOSStub_9d65 {
  strings:
    $key_9d65 = { c9 0d [2] bd 15 [2] fa 17 [2] bd 06 [2] f3 0a [2] ff 00 [2] e8 0b [2] f3 45 [2] ce }

  condition:
    any of them
}