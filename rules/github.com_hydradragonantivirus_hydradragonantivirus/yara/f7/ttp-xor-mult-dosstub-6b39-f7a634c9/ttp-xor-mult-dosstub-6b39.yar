rule TTP_XOR_MULT_DOSStub_6b39 {
  strings:
    $key_6b39 = { 3f 51 [2] 4b 49 [2] 0c 4b [2] 4b 5a [2] 05 56 [2] 09 5c [2] 1e 57 [2] 05 19 [2] 38 }

  condition:
    any of them
}