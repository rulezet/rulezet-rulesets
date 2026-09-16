rule TTP_XOR_MULT_DOSStub_9de7 {
  strings:
    $key_9de7 = { c9 8f [2] bd 97 [2] fa 95 [2] bd 84 [2] f3 88 [2] ff 82 [2] e8 89 [2] f3 c7 [2] ce }

  condition:
    any of them
}