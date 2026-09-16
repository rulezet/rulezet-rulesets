rule TTP_XOR_MULT_DOSStub_e8d9 {
  strings:
    $key_e8d9 = { bc b1 [2] c8 a9 [2] 8f ab [2] c8 ba [2] 86 b6 [2] 8a bc [2] 9d b7 [2] 86 f9 [2] bb }

  condition:
    any of them
}