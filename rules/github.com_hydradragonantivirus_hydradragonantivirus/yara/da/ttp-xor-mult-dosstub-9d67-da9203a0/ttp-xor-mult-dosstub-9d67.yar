rule TTP_XOR_MULT_DOSStub_9d67 {
  strings:
    $key_9d67 = { c9 0f [2] bd 17 [2] fa 15 [2] bd 04 [2] f3 08 [2] ff 02 [2] e8 09 [2] f3 47 [2] ce }

  condition:
    any of them
}