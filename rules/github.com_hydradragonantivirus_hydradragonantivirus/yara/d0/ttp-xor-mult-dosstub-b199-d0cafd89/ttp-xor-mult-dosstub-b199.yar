rule TTP_XOR_MULT_DOSStub_b199 {
  strings:
    $key_b199 = { e5 f1 [2] 91 e9 [2] d6 eb [2] 91 fa [2] df f6 [2] d3 fc [2] c4 f7 [2] df b9 [2] e2 }

  condition:
    any of them
}