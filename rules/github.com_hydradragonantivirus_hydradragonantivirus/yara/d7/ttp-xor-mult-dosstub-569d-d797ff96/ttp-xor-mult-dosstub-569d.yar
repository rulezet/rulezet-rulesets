rule TTP_XOR_MULT_DOSStub_569d {
  strings:
    $key_569d = { 02 f5 [2] 76 ed [2] 31 ef [2] 76 fe [2] 38 f2 [2] 34 f8 [2] 23 f3 [2] 38 bd [2] 05 }

  condition:
    any of them
}