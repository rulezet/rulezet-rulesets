rule TTP_XOR_MULT_DOSStub_5f29 {
  strings:
    $key_5f29 = { 0b 41 [2] 7f 59 [2] 38 5b [2] 7f 4a [2] 31 46 [2] 3d 4c [2] 2a 47 [2] 31 09 [2] 0c }

  condition:
    any of them
}