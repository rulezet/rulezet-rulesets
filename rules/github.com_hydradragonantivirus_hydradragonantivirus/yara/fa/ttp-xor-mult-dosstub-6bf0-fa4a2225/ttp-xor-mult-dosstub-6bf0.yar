rule TTP_XOR_MULT_DOSStub_6bf0 {
  strings:
    $key_6bf0 = { 3f 98 [2] 4b 80 [2] 0c 82 [2] 4b 93 [2] 05 9f [2] 09 95 [2] 1e 9e [2] 05 d0 [2] 38 }

  condition:
    any of them
}