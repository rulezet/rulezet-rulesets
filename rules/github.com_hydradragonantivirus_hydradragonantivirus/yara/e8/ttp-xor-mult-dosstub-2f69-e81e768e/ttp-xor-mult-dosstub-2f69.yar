rule TTP_XOR_MULT_DOSStub_2f69 {
  strings:
    $key_2f69 = { 7b 01 [2] 0f 19 [2] 48 1b [2] 0f 0a [2] 41 06 [2] 4d 0c [2] 5a 07 [2] 41 49 [2] 7c }

  condition:
    any of them
}