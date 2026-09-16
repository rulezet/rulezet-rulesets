rule TTP_XOR_MULT_DOSStub_a08e {
  strings:
    $key_a08e = { f4 e6 [2] 80 fe [2] c7 fc [2] 80 ed [2] ce e1 [2] c2 eb [2] d5 e0 [2] ce ae [2] f3 }

  condition:
    any of them
}