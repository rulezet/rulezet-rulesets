rule TTP_XOR_MULT_DOSStub_9de6 {
  strings:
    $key_9de6 = { c9 8e [2] bd 96 [2] fa 94 [2] bd 85 [2] f3 89 [2] ff 83 [2] e8 88 [2] f3 c6 [2] ce }

  condition:
    any of them
}