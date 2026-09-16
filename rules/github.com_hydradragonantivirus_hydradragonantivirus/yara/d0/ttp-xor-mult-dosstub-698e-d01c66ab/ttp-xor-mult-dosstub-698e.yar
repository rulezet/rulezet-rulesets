rule TTP_XOR_MULT_DOSStub_698e {
  strings:
    $key_698e = { 3d e6 [2] 49 fe [2] 0e fc [2] 49 ed [2] 07 e1 [2] 0b eb [2] 1c e0 [2] 07 ae [2] 3a }

  condition:
    any of them
}