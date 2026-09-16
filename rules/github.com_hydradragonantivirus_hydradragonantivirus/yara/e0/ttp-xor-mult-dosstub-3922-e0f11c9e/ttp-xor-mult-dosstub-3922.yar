rule TTP_XOR_MULT_DOSStub_3922 {
  strings:
    $key_3922 = { 6d 4a [2] 19 52 [2] 5e 50 [2] 19 41 [2] 57 4d [2] 5b 47 [2] 4c 4c [2] 57 02 [2] 6a }

  condition:
    any of them
}