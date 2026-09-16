rule TTP_XOR_MULT_DOSStub_6be3 {
  strings:
    $key_6be3 = { 3f 8b [2] 4b 93 [2] 0c 91 [2] 4b 80 [2] 05 8c [2] 09 86 [2] 1e 8d [2] 05 c3 [2] 38 }

  condition:
    any of them
}