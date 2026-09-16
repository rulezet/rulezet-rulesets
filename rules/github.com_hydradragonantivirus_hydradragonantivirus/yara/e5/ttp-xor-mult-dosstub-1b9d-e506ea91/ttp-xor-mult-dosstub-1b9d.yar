rule TTP_XOR_MULT_DOSStub_1b9d {
  strings:
    $key_1b9d = { 4f f5 [2] 3b ed [2] 7c ef [2] 3b fe [2] 75 f2 [2] 79 f8 [2] 6e f3 [2] 75 bd [2] 48 }

  condition:
    any of them
}