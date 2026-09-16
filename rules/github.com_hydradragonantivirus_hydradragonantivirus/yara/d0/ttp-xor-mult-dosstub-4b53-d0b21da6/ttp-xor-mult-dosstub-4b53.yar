rule TTP_XOR_MULT_DOSStub_4b53 {
  strings:
    $key_4b53 = { 1f 3b [2] 6b 23 [2] 2c 21 [2] 6b 30 [2] 25 3c [2] 29 36 [2] 3e 3d [2] 25 73 [2] 18 }

  condition:
    any of them
}