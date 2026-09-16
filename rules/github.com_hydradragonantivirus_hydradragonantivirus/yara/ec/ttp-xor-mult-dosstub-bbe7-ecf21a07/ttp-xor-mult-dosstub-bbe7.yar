rule TTP_XOR_MULT_DOSStub_bbe7 {
  strings:
    $key_bbe7 = { ef 8f [2] 9b 97 [2] dc 95 [2] 9b 84 [2] d5 88 [2] d9 82 [2] ce 89 [2] d5 c7 [2] e8 }

  condition:
    any of them
}