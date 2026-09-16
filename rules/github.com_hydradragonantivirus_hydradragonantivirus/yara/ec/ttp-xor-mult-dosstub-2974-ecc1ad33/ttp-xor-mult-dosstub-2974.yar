rule TTP_XOR_MULT_DOSStub_2974 {
  strings:
    $key_2974 = { 7d 1c [2] 09 04 [2] 4e 06 [2] 09 17 [2] 47 1b [2] 4b 11 [2] 5c 1a [2] 47 54 [2] 7a }

  condition:
    any of them
}