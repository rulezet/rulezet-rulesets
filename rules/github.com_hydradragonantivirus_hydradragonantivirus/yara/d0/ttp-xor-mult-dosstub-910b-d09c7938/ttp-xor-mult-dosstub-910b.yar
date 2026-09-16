rule TTP_XOR_MULT_DOSStub_910b {
  strings:
    $key_910b = { c5 63 [2] b1 7b [2] f6 79 [2] b1 68 [2] ff 64 [2] f3 6e [2] e4 65 [2] ff 2b [2] c2 }

  condition:
    any of them
}