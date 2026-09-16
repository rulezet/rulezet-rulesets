rule TTP_XOR_MULT_DOSStub_9d2a {
  strings:
    $key_9d2a = { c9 42 [2] bd 5a [2] fa 58 [2] bd 49 [2] f3 45 [2] ff 4f [2] e8 44 [2] f3 0a [2] ce }

  condition:
    any of them
}