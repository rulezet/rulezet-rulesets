rule TTP_XOR_MULT_DOSStub_479d {
  strings:
    $key_479d = { 13 f5 [2] 67 ed [2] 20 ef [2] 67 fe [2] 29 f2 [2] 25 f8 [2] 32 f3 [2] 29 bd [2] 14 }

  condition:
    any of them
}