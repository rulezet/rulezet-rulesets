rule TTP_XOR_MULT_DOSStub_910c {
  strings:
    $key_910c = { c5 64 [2] b1 7c [2] f6 7e [2] b1 6f [2] ff 63 [2] f3 69 [2] e4 62 [2] ff 2c [2] c2 }

  condition:
    any of them
}