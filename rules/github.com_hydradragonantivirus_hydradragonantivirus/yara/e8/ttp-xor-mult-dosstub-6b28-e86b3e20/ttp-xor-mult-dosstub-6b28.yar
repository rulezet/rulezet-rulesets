rule TTP_XOR_MULT_DOSStub_6b28 {
  strings:
    $key_6b28 = { 3f 40 [2] 4b 58 [2] 0c 5a [2] 4b 4b [2] 05 47 [2] 09 4d [2] 1e 46 [2] 05 08 [2] 38 }

  condition:
    any of them
}