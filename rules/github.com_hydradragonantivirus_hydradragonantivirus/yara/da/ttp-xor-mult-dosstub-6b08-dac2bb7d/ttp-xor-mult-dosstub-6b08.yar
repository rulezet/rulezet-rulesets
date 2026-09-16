rule TTP_XOR_MULT_DOSStub_6b08 {
  strings:
    $key_6b08 = { 3f 60 [2] 4b 78 [2] 0c 7a [2] 4b 6b [2] 05 67 [2] 09 6d [2] 1e 66 [2] 05 28 [2] 38 }

  condition:
    any of them
}