rule TTP_XOR_MULT_DOSStub_916f {
  strings:
    $key_916f = { c5 07 [2] b1 1f [2] f6 1d [2] b1 0c [2] ff 00 [2] f3 0a [2] e4 01 [2] ff 4f [2] c2 }

  condition:
    any of them
}