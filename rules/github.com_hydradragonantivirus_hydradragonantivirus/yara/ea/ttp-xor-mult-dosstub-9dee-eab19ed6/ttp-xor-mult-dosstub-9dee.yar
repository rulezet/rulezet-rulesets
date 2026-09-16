rule TTP_XOR_MULT_DOSStub_9dee {
  strings:
    $key_9dee = { c9 86 [2] bd 9e [2] fa 9c [2] bd 8d [2] f3 81 [2] ff 8b [2] e8 80 [2] f3 ce [2] ce }

  condition:
    any of them
}