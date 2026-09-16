rule TTP_XOR_MULT_DOSStub_2b53 {
  strings:
    $key_2b53 = { 7f 3b [2] 0b 23 [2] 4c 21 [2] 0b 30 [2] 45 3c [2] 49 36 [2] 5e 3d [2] 45 73 [2] 78 }

  condition:
    any of them
}