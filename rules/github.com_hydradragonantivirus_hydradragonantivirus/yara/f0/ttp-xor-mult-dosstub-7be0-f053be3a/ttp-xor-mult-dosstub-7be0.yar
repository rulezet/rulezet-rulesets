rule TTP_XOR_MULT_DOSStub_7be0 {
  strings:
    $key_7be0 = { 2f 88 [2] 5b 90 [2] 1c 92 [2] 5b 83 [2] 15 8f [2] 19 85 [2] 0e 8e [2] 15 c0 [2] 28 }

  condition:
    any of them
}