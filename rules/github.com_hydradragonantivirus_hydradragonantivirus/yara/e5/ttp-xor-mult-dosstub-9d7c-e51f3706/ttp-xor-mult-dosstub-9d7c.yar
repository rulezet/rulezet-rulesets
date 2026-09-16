rule TTP_XOR_MULT_DOSStub_9d7c {
  strings:
    $key_9d7c = { c9 14 [2] bd 0c [2] fa 0e [2] bd 1f [2] f3 13 [2] ff 19 [2] e8 12 [2] f3 5c [2] ce }

  condition:
    any of them
}