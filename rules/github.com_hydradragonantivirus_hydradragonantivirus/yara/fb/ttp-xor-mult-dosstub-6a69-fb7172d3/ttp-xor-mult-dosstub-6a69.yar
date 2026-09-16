rule TTP_XOR_MULT_DOSStub_6a69 {
  strings:
    $key_6a69 = { 3e 01 [2] 4a 19 [2] 0d 1b [2] 4a 0a [2] 04 06 [2] 08 0c [2] 1f 07 [2] 04 49 [2] 39 }

  condition:
    any of them
}