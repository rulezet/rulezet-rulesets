rule TTP_XOR_MULT_DOSStub_2f28 {
  strings:
    $key_2f28 = { 7b 40 [2] 0f 58 [2] 48 5a [2] 0f 4b [2] 41 47 [2] 4d 4d [2] 5a 46 [2] 41 08 [2] 7c }

  condition:
    any of them
}