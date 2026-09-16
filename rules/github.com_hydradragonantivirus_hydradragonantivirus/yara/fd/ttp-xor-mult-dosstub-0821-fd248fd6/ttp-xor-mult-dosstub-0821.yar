rule TTP_XOR_MULT_DOSStub_0821 {
  strings:
    $key_0821 = { 5c 49 [2] 28 51 [2] 6f 53 [2] 28 42 [2] 66 4e [2] 6a 44 [2] 7d 4f [2] 66 01 [2] 5b }

  condition:
    any of them
}