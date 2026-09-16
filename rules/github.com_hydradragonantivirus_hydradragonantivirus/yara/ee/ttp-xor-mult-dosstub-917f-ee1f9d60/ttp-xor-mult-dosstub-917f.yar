rule TTP_XOR_MULT_DOSStub_917f {
  strings:
    $key_917f = { c5 17 [2] b1 0f [2] f6 0d [2] b1 1c [2] ff 10 [2] f3 1a [2] e4 11 [2] ff 5f [2] c2 }

  condition:
    any of them
}