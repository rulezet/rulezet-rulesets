rule TTP_XOR_MULT_DOSStub_2e99 {
  strings:
    $key_2e99 = { 7a f1 [2] 0e e9 [2] 49 eb [2] 0e fa [2] 40 f6 [2] 4c fc [2] 5b f7 [2] 40 b9 [2] 7d }

  condition:
    any of them
}