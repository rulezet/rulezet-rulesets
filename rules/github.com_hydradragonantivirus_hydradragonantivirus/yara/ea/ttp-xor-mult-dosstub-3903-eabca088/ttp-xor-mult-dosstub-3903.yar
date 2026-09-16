rule TTP_XOR_MULT_DOSStub_3903 {
  strings:
    $key_3903 = { 6d 6b [2] 19 73 [2] 5e 71 [2] 19 60 [2] 57 6c [2] 5b 66 [2] 4c 6d [2] 57 23 [2] 6a }

  condition:
    any of them
}