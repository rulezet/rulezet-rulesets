rule TTP_XOR_MULT_DOSStub_6b18 {
  strings:
    $key_6b18 = { 3f 70 [2] 4b 68 [2] 0c 6a [2] 4b 7b [2] 05 77 [2] 09 7d [2] 1e 76 [2] 05 38 [2] 38 }

  condition:
    any of them
}