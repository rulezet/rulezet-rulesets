rule TTP_XOR_MULT_DOSStub_cbe3 {
  strings:
    $key_cbe3 = { 9f 8b [2] eb 93 [2] ac 91 [2] eb 80 [2] a5 8c [2] a9 86 [2] be 8d [2] a5 c3 [2] 98 }

  condition:
    any of them
}