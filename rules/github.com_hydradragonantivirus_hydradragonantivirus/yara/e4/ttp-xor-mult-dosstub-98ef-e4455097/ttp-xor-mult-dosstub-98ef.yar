rule TTP_XOR_MULT_DOSStub_98ef {
  strings:
    $key_98ef = { cc 87 [2] b8 9f [2] ff 9d [2] b8 8c [2] f6 80 [2] fa 8a [2] ed 81 [2] f6 cf [2] cb }

  condition:
    any of them
}