rule TTP_XOR_MULT_DOSStub_7b9d {
  strings:
    $key_7b9d = { 2f f5 [2] 5b ed [2] 1c ef [2] 5b fe [2] 15 f2 [2] 19 f8 [2] 0e f3 [2] 15 bd [2] 28 }

  condition:
    any of them
}