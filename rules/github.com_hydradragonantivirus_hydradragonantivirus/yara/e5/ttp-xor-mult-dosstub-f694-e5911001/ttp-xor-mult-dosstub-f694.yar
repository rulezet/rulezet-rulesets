rule TTP_XOR_MULT_DOSStub_f694 {
  strings:
    $key_f694 = { a2 fc [2] d6 e4 [2] 91 e6 [2] d6 f7 [2] 98 fb [2] 94 f1 [2] 83 fa [2] 98 b4 [2] a5 }

  condition:
    any of them
}