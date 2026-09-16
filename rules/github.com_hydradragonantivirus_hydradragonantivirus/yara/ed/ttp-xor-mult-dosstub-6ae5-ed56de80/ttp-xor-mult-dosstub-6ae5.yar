rule TTP_XOR_MULT_DOSStub_6ae5 {
  strings:
    $key_6ae5 = { 3e 8d [2] 4a 95 [2] 0d 97 [2] 4a 86 [2] 04 8a [2] 08 80 [2] 1f 8b [2] 04 c5 [2] 39 }

  condition:
    any of them
}