rule TTP_XOR_MULT_DOSStub_cc8e {
  strings:
    $key_cc8e = { 98 e6 [2] ec fe [2] ab fc [2] ec ed [2] a2 e1 [2] ae eb [2] b9 e0 [2] a2 ae [2] 9f }

  condition:
    any of them
}