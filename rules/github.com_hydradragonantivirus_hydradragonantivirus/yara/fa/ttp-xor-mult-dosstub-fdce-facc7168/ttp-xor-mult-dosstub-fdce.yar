rule TTP_XOR_MULT_DOSStub_fdce {
  strings:
    $key_fdce = { a9 a6 [2] dd be [2] 9a bc [2] dd ad [2] 93 a1 [2] 9f ab [2] 88 a0 [2] 93 ee [2] ae }

  condition:
    any of them
}