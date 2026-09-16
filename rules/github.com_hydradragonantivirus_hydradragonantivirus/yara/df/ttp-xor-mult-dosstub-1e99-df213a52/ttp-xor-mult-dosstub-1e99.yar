rule TTP_XOR_MULT_DOSStub_1e99 {
  strings:
    $key_1e99 = { 4a f1 [2] 3e e9 [2] 79 eb [2] 3e fa [2] 70 f6 [2] 7c fc [2] 6b f7 [2] 70 b9 [2] 4d }

  condition:
    any of them
}