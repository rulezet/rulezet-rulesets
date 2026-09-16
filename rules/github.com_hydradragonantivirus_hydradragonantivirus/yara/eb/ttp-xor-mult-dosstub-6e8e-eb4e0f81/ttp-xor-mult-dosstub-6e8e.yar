rule TTP_XOR_MULT_DOSStub_6e8e {
  strings:
    $key_6e8e = { 3a e6 [2] 4e fe [2] 09 fc [2] 4e ed [2] 00 e1 [2] 0c eb [2] 1b e0 [2] 00 ae [2] 3d }

  condition:
    any of them
}