rule TTP_XOR_MULT_DOSStub_c18e {
  strings:
    $key_c18e = { 95 e6 [2] e1 fe [2] a6 fc [2] e1 ed [2] af e1 [2] a3 eb [2] b4 e0 [2] af ae [2] 92 }

  condition:
    any of them
}