rule TTP_XOR_MULT_DOSStub_2684 {
  strings:
    $key_2684 = { 72 ec [2] 06 f4 [2] 41 f6 [2] 06 e7 [2] 48 eb [2] 44 e1 [2] 53 ea [2] 48 a4 [2] 75 }

  condition:
    any of them
}