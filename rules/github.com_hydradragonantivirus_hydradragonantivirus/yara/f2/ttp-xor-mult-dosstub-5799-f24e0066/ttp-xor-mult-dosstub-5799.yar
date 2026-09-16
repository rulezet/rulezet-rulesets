rule TTP_XOR_MULT_DOSStub_5799 {
  strings:
    $key_5799 = { 03 f1 [2] 77 e9 [2] 30 eb [2] 77 fa [2] 39 f6 [2] 35 fc [2] 22 f7 [2] 39 b9 [2] 04 }

  condition:
    any of them
}