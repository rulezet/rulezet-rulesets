rule TTP_XOR_MULT_DOSStub_0b6b {
  strings:
    $key_0b6b = { 5f 03 [2] 2b 1b [2] 6c 19 [2] 2b 08 [2] 65 04 [2] 69 0e [2] 7e 05 [2] 65 4b [2] 58 }

  condition:
    any of them
}