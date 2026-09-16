rule TTP_XOR_MULT_DOSStub_0979 {
  strings:
    $key_0979 = { 5d 11 [2] 29 09 [2] 6e 0b [2] 29 1a [2] 67 16 [2] 6b 1c [2] 7c 17 [2] 67 59 [2] 5a }

  condition:
    any of them
}