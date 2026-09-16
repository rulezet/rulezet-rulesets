rule TTP_XOR_MULT_DOSStub_5b53 {
  strings:
    $key_5b53 = { 0f 3b [2] 7b 23 [2] 3c 21 [2] 7b 30 [2] 35 3c [2] 39 36 [2] 2e 3d [2] 35 73 [2] 08 }

  condition:
    any of them
}