rule TTP_XOR_MULT_DOSStub_c58e {
  strings:
    $key_c58e = { 91 e6 [2] e5 fe [2] a2 fc [2] e5 ed [2] ab e1 [2] a7 eb [2] b0 e0 [2] ab ae [2] 96 }

  condition:
    any of them
}