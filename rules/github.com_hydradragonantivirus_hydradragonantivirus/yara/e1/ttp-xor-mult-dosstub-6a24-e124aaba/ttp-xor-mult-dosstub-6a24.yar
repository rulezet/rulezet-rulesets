rule TTP_XOR_MULT_DOSStub_6a24 {
  strings:
    $key_6a24 = { 3e 4c [2] 4a 54 [2] 0d 56 [2] 4a 47 [2] 04 4b [2] 08 41 [2] 1f 4a [2] 04 04 [2] 39 }

  condition:
    any of them
}