rule TTP_XOR_MULT_DOSStub_5be3 {
  strings:
    $key_5be3 = { 0f 8b [2] 7b 93 [2] 3c 91 [2] 7b 80 [2] 35 8c [2] 39 86 [2] 2e 8d [2] 35 c3 [2] 08 }

  condition:
    any of them
}