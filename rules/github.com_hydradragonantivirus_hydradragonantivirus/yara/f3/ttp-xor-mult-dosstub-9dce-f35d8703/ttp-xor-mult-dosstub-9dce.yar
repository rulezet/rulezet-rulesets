rule TTP_XOR_MULT_DOSStub_9dce {
  strings:
    $key_9dce = { c9 a6 [2] bd be [2] fa bc [2] bd ad [2] f3 a1 [2] ff ab [2] e8 a0 [2] f3 ee [2] ce }

  condition:
    any of them
}