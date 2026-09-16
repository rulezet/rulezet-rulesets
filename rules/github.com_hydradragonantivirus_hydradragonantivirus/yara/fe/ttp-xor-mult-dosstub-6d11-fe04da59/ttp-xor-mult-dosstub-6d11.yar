rule TTP_XOR_MULT_DOSStub_6d11 {
  strings:
    $key_6d11 = { 39 79 [2] 4d 61 [2] 0a 63 [2] 4d 72 [2] 03 7e [2] 0f 74 [2] 18 7f [2] 03 31 [2] 3e }

  condition:
    any of them
}