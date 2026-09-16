rule TTP_XOR_MULT_DOSStub_fe8e {
  strings:
    $key_fe8e = { aa e6 [2] de fe [2] 99 fc [2] de ed [2] 90 e1 [2] 9c eb [2] 8b e0 [2] 90 ae [2] ad }

  condition:
    any of them
}