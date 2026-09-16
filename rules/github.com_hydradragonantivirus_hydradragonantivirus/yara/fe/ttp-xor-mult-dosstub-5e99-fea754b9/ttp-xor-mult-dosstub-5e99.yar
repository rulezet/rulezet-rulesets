rule TTP_XOR_MULT_DOSStub_5e99 {
  strings:
    $key_5e99 = { 0a f1 [2] 7e e9 [2] 39 eb [2] 7e fa [2] 30 f6 [2] 3c fc [2] 2b f7 [2] 30 b9 [2] 0d }

  condition:
    any of them
}