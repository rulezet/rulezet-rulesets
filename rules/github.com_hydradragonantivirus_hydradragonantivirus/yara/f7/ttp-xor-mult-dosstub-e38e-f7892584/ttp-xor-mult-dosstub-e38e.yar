rule TTP_XOR_MULT_DOSStub_e38e {
  strings:
    $key_e38e = { b7 e6 [2] c3 fe [2] 84 fc [2] c3 ed [2] 8d e1 [2] 81 eb [2] 96 e0 [2] 8d ae [2] b0 }

  condition:
    any of them
}