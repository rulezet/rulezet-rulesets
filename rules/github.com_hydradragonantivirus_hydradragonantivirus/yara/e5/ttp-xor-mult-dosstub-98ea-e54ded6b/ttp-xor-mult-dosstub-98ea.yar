rule TTP_XOR_MULT_DOSStub_98ea {
  strings:
    $key_98ea = { cc 82 [2] b8 9a [2] ff 98 [2] b8 89 [2] f6 85 [2] fa 8f [2] ed 84 [2] f6 ca [2] cb }

  condition:
    any of them
}