rule TTP_XOR_MULT_DOSStub_6bf9 {
  strings:
    $key_6bf9 = { 3f 91 [2] 4b 89 [2] 0c 8b [2] 4b 9a [2] 05 96 [2] 09 9c [2] 1e 97 [2] 05 d9 [2] 38 }

  condition:
    any of them
}