rule TTP_XOR_MULT_DOSStub_f6cb {
  strings:
    $key_f6cb = { a2 a3 [2] d6 bb [2] 91 b9 [2] d6 a8 [2] 98 a4 [2] 94 ae [2] 83 a5 [2] 98 eb [2] a5 }

  condition:
    any of them
}