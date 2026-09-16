rule TTP_XOR_MULT_DOSStub_6f29 {
  strings:
    $key_6f29 = { 3b 41 [2] 4f 59 [2] 08 5b [2] 4f 4a [2] 01 46 [2] 0d 4c [2] 1a 47 [2] 01 09 [2] 3c }

  condition:
    any of them
}