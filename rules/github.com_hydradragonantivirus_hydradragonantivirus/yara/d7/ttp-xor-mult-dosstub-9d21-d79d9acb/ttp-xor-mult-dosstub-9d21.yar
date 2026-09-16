rule TTP_XOR_MULT_DOSStub_9d21 {
  strings:
    $key_9d21 = { c9 49 [2] bd 51 [2] fa 53 [2] bd 42 [2] f3 4e [2] ff 44 [2] e8 4f [2] f3 01 [2] ce }

  condition:
    any of them
}