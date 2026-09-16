rule TTP_XOR_MULT_DOSStub_bb36 {
  strings:
    $key_bb36 = { ef 5e [2] 9b 46 [2] dc 44 [2] 9b 55 [2] d5 59 [2] d9 53 [2] ce 58 [2] d5 16 [2] e8 }

  condition:
    any of them
}