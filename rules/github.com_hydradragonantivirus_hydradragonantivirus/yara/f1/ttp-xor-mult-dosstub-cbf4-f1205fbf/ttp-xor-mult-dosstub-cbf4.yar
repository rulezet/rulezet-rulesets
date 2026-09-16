rule TTP_XOR_MULT_DOSStub_cbf4 {
  strings:
    $key_cbf4 = { 9f 9c [2] eb 84 [2] ac 86 [2] eb 97 [2] a5 9b [2] a9 91 [2] be 9a [2] a5 d4 [2] 98 }

  condition:
    any of them
}