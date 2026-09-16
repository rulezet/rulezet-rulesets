rule TTP_XOR_MULT_DOSStub_fe99 {
  strings:
    $key_fe99 = { aa f1 [2] de e9 [2] 99 eb [2] de fa [2] 90 f6 [2] 9c fc [2] 8b f7 [2] 90 b9 [2] ad }

  condition:
    any of them
}