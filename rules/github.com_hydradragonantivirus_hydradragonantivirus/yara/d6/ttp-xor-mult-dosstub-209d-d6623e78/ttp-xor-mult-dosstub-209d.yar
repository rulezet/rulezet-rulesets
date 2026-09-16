rule TTP_XOR_MULT_DOSStub_209d {
  strings:
    $key_209d = { 74 f5 [2] 00 ed [2] 47 ef [2] 00 fe [2] 4e f2 [2] 42 f8 [2] 55 f3 [2] 4e bd [2] 73 }

  condition:
    any of them
}