rule TTP_XOR_MULT_DOSStub_9899 {
  strings:
    $key_9899 = { cc f1 [2] b8 e9 [2] ff eb [2] b8 fa [2] f6 f6 [2] fa fc [2] ed f7 [2] f6 b9 [2] cb }

  condition:
    any of them
}