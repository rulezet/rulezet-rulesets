rule TTP_XOR_MULT_DOSStub_0b64 {
  strings:
    $key_0b64 = { 5f 0c [2] 2b 14 [2] 6c 16 [2] 2b 07 [2] 65 0b [2] 69 01 [2] 7e 0a [2] 65 44 [2] 58 }

  condition:
    any of them
}