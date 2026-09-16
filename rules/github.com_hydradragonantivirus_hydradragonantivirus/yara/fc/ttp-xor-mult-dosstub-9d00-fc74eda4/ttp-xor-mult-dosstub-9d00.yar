rule TTP_XOR_MULT_DOSStub_9d00 {
  strings:
    $key_9d00 = { c9 68 [2] bd 70 [2] fa 72 [2] bd 63 [2] f3 6f [2] ff 65 [2] e8 6e [2] f3 20 [2] ce }

  condition:
    any of them
}