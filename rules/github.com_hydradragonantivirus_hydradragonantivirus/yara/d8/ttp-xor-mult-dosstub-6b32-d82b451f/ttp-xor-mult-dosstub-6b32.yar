rule TTP_XOR_MULT_DOSStub_6b32 {
  strings:
    $key_6b32 = { 3f 5a [2] 4b 42 [2] 0c 40 [2] 4b 51 [2] 05 5d [2] 09 57 [2] 1e 5c [2] 05 12 [2] 38 }

  condition:
    any of them
}