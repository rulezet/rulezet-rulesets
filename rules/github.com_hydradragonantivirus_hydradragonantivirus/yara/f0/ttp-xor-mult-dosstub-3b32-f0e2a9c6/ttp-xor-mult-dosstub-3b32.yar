rule TTP_XOR_MULT_DOSStub_3b32 {
  strings:
    $key_3b32 = { 6f 5a [2] 1b 42 [2] 5c 40 [2] 1b 51 [2] 55 5d [2] 59 57 [2] 4e 5c [2] 55 12 [2] 68 }

  condition:
    any of them
}