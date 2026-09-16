rule TTP_XOR_MULT_DOSStub_c483 {
  strings:
    $key_c483 = { 90 eb [2] e4 f3 [2] a3 f1 [2] e4 e0 [2] aa ec [2] a6 e6 [2] b1 ed [2] aa a3 [2] 97 }

  condition:
    any of them
}