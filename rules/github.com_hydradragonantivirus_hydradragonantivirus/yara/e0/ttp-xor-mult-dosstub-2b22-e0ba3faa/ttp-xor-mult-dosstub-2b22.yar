rule TTP_XOR_MULT_DOSStub_2b22 {
  strings:
    $key_2b22 = { 7f 4a [2] 0b 52 [2] 4c 50 [2] 0b 41 [2] 45 4d [2] 49 47 [2] 5e 4c [2] 45 02 [2] 78 }

  condition:
    any of them
}