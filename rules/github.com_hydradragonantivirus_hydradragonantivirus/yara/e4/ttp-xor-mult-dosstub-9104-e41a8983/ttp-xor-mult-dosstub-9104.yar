rule TTP_XOR_MULT_DOSStub_9104 {
  strings:
    $key_9104 = { c5 6c [2] b1 74 [2] f6 76 [2] b1 67 [2] ff 6b [2] f3 61 [2] e4 6a [2] ff 24 [2] c2 }

  condition:
    any of them
}