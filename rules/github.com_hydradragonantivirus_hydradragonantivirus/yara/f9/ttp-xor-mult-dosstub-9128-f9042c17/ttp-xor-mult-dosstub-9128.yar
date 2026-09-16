rule TTP_XOR_MULT_DOSStub_9128 {
  strings:
    $key_9128 = { c5 40 [2] b1 58 [2] f6 5a [2] b1 4b [2] ff 47 [2] f3 4d [2] e4 46 [2] ff 08 [2] c2 }

  condition:
    any of them
}