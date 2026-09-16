rule TTP_XOR_MULT_DOSStub_0f29 {
  strings:
    $key_0f29 = { 5b 41 [2] 2f 59 [2] 68 5b [2] 2f 4a [2] 61 46 [2] 6d 4c [2] 7a 47 [2] 61 09 [2] 5c }

  condition:
    any of them
}