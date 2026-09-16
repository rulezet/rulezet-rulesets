rule TTP_XOR_MULT_DOSStub_9d6d {
  strings:
    $key_9d6d = { c9 05 [2] bd 1d [2] fa 1f [2] bd 0e [2] f3 02 [2] ff 08 [2] e8 03 [2] f3 4d [2] ce }

  condition:
    any of them
}