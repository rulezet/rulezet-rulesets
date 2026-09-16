rule TTP_XOR_MULT_DOSStub_3b53 {
  strings:
    $key_3b53 = { 6f 3b [2] 1b 23 [2] 5c 21 [2] 1b 30 [2] 55 3c [2] 59 36 [2] 4e 3d [2] 55 73 [2] 68 }

  condition:
    any of them
}