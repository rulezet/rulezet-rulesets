rule TTP_XOR_MULT_DOSStub_d9ce {
  strings:
    $key_d9ce = { 8d a6 [2] f9 be [2] be bc [2] f9 ad [2] b7 a1 [2] bb ab [2] ac a0 [2] b7 ee [2] 8a }

  condition:
    any of them
}