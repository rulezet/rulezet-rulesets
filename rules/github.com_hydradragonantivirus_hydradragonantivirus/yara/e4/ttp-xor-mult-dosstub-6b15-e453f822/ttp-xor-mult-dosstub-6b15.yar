rule TTP_XOR_MULT_DOSStub_6b15 {
  strings:
    $key_6b15 = { 3f 7d [2] 4b 65 [2] 0c 67 [2] 4b 76 [2] 05 7a [2] 09 70 [2] 1e 7b [2] 05 35 [2] 38 }

  condition:
    any of them
}