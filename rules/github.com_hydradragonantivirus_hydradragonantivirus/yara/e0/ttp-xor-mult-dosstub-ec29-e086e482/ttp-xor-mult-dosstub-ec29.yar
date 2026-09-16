rule TTP_XOR_MULT_DOSStub_ec29 {
  strings:
    $key_ec29 = { b8 41 [2] cc 59 [2] 8b 5b [2] cc 4a [2] 82 46 [2] 8e 4c [2] 99 47 [2] 82 09 [2] bf }

  condition:
    any of them
}