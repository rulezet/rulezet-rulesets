rule TTP_XOR_MULT_DOSStub_987a {
  strings:
    $key_987a = { cc 12 [2] b8 0a [2] ff 08 [2] b8 19 [2] f6 15 [2] fa 1f [2] ed 14 [2] f6 5a [2] cb }

  condition:
    any of them
}