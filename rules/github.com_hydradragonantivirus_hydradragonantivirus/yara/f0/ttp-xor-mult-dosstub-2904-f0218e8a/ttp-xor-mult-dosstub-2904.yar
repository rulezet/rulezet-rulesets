rule TTP_XOR_MULT_DOSStub_2904 {
  strings:
    $key_2904 = { 7d 6c [2] 09 74 [2] 4e 76 [2] 09 67 [2] 47 6b [2] 4b 61 [2] 5c 6a [2] 47 24 [2] 7a }

  condition:
    any of them
}