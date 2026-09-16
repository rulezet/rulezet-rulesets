rule TTP_XOR_MULT_DOSStub_6a00 {
  strings:
    $key_6a00 = { 3e 68 [2] 4a 70 [2] 0d 72 [2] 4a 63 [2] 04 6f [2] 08 65 [2] 1f 6e [2] 04 20 [2] 39 }

  condition:
    any of them
}