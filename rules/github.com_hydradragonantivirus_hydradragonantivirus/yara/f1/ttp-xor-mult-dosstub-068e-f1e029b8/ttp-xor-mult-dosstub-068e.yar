rule TTP_XOR_MULT_DOSStub_068e {
  strings:
    $key_068e = { 52 e6 [2] 26 fe [2] 61 fc [2] 26 ed [2] 68 e1 [2] 64 eb [2] 73 e0 [2] 68 ae [2] 55 }

  condition:
    any of them
}