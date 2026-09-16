rule TTP_XOR_MULT_DOSStub_98ec {
  strings:
    $key_98ec = { cc 84 [2] b8 9c [2] ff 9e [2] b8 8f [2] f6 83 [2] fa 89 [2] ed 82 [2] f6 cc [2] cb }

  condition:
    any of them
}