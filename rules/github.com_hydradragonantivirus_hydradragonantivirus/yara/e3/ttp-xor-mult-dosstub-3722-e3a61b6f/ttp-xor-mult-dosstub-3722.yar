rule TTP_XOR_MULT_DOSStub_3722 {
  strings:
    $key_3722 = { 63 4a [2] 17 52 [2] 50 50 [2] 17 41 [2] 59 4d [2] 55 47 [2] 42 4c [2] 59 02 [2] 64 }

  condition:
    any of them
}