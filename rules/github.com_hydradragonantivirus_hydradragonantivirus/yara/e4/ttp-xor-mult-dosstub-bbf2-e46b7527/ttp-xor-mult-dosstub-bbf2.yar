rule TTP_XOR_MULT_DOSStub_bbf2 {
  strings:
    $key_bbf2 = { ef 9a [2] 9b 82 [2] dc 80 [2] 9b 91 [2] d5 9d [2] d9 97 [2] ce 9c [2] d5 d2 [2] e8 }

  condition:
    any of them
}