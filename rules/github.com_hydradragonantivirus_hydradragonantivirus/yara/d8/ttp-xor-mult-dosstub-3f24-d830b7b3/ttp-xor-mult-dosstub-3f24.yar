rule TTP_XOR_MULT_DOSStub_3f24 {
  strings:
    $key_3f24 = { 6b 4c [2] 1f 54 [2] 58 56 [2] 1f 47 [2] 51 4b [2] 5d 41 [2] 4a 4a [2] 51 04 [2] 6c }

  condition:
    any of them
}