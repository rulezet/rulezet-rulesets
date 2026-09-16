rule TTP_XOR_MULT_DOSStub_4b32 {
  strings:
    $key_4b32 = { 1f 5a [2] 6b 42 [2] 2c 40 [2] 6b 51 [2] 25 5d [2] 29 57 [2] 3e 5c [2] 25 12 [2] 18 }

  condition:
    any of them
}