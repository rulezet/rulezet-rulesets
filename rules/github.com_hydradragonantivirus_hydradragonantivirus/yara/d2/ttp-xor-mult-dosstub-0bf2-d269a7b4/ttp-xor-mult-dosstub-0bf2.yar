rule TTP_XOR_MULT_DOSStub_0bf2 {
  strings:
    $key_0bf2 = { 5f 9a [2] 2b 82 [2] 6c 80 [2] 2b 91 [2] 65 9d [2] 69 97 [2] 7e 9c [2] 65 d2 [2] 58 }

  condition:
    any of them
}