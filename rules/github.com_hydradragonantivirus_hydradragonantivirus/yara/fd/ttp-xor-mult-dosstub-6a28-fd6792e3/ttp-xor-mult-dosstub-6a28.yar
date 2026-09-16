rule TTP_XOR_MULT_DOSStub_6a28 {
  strings:
    $key_6a28 = { 3e 40 [2] 4a 58 [2] 0d 5a [2] 4a 4b [2] 04 47 [2] 08 4d [2] 1f 46 [2] 04 08 [2] 39 }

  condition:
    any of them
}