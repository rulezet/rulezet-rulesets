rule TTP_XOR_MULT_DOSStub_9dfa {
  strings:
    $key_9dfa = { c9 92 [2] bd 8a [2] fa 88 [2] bd 99 [2] f3 95 [2] ff 9f [2] e8 94 [2] f3 da [2] ce }

  condition:
    any of them
}