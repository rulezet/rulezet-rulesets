rule TTP_XOR_MULT_DOSStub_1b53 {
  strings:
    $key_1b53 = { 4f 3b [2] 3b 23 [2] 7c 21 [2] 3b 30 [2] 75 3c [2] 79 36 [2] 6e 3d [2] 75 73 [2] 48 }

  condition:
    any of them
}