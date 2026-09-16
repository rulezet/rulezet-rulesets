rule TTP_XOR_MULT_DOSStub_9d30 {
  strings:
    $key_9d30 = { c9 58 [2] bd 40 [2] fa 42 [2] bd 53 [2] f3 5f [2] ff 55 [2] e8 5e [2] f3 10 [2] ce }

  condition:
    any of them
}