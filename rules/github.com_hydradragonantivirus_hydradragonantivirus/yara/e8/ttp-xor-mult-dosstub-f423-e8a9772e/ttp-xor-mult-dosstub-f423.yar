rule TTP_XOR_MULT_DOSStub_f423 {
  strings:
    $key_f423 = { a0 4b [2] d4 53 [2] 93 51 [2] d4 40 [2] 9a 4c [2] 96 46 [2] 81 4d [2] 9a 03 [2] a7 }

  condition:
    any of them
}