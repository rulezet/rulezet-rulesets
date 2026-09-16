rule TTP_XOR_MULT_DOSStub_68d9 {
  strings:
    $key_68d9 = { 3c b1 [2] 48 a9 [2] 0f ab [2] 48 ba [2] 06 b6 [2] 0a bc [2] 1d b7 [2] 06 f9 [2] 3b }

  condition:
    any of them
}