rule TTP_XOR_MULT_DOSStub_0069 {
  strings:
    $key_0069 = { 54 01 [2] 20 19 [2] 67 1b [2] 20 0a [2] 6e 06 [2] 62 0c [2] 75 07 [2] 6e 49 [2] 53 }

  condition:
    any of them
}