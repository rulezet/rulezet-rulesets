rule TTP_XOR_MULT_DOSStub_9d2e {
  strings:
    $key_9d2e = { c9 46 [2] bd 5e [2] fa 5c [2] bd 4d [2] f3 41 [2] ff 4b [2] e8 40 [2] f3 0e [2] ce }

  condition:
    any of them
}