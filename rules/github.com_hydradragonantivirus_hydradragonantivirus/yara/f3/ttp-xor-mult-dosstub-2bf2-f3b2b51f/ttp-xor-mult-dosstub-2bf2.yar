rule TTP_XOR_MULT_DOSStub_2bf2 {
  strings:
    $key_2bf2 = { 7f 9a [2] 0b 82 [2] 4c 80 [2] 0b 91 [2] 45 9d [2] 49 97 [2] 5e 9c [2] 45 d2 [2] 78 }

  condition:
    any of them
}