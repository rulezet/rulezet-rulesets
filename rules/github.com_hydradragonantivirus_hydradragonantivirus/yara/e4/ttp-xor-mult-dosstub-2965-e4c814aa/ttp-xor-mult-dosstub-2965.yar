rule TTP_XOR_MULT_DOSStub_2965 {
  strings:
    $key_2965 = { 7d 0d [2] 09 15 [2] 4e 17 [2] 09 06 [2] 47 0a [2] 4b 00 [2] 5c 0b [2] 47 45 [2] 7a }

  condition:
    any of them
}