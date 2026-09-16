rule TTP_XOR_MULT_DOSStub_db99 {
  strings:
    $key_db99 = { 8f f1 [2] fb e9 [2] bc eb [2] fb fa [2] b5 f6 [2] b9 fc [2] ae f7 [2] b5 b9 [2] 88 }

  condition:
    any of them
}