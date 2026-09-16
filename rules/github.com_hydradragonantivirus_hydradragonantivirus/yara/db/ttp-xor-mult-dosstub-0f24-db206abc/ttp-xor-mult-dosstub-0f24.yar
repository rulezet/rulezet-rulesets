rule TTP_XOR_MULT_DOSStub_0f24 {
  strings:
    $key_0f24 = { 5b 4c [2] 2f 54 [2] 68 56 [2] 2f 47 [2] 61 4b [2] 6d 41 [2] 7a 4a [2] 61 04 [2] 5c }

  condition:
    any of them
}