rule TTP_XOR_MULT_DOSStub_9100 {
  strings:
    $key_9100 = { c5 68 [2] b1 70 [2] f6 72 [2] b1 63 [2] ff 6f [2] f3 65 [2] e4 6e [2] ff 20 [2] c2 }

  condition:
    any of them
}