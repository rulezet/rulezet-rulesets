rule TTP_XOR_MULT_DOSStub_649c {
  strings:
    $key_649c = { 30 f4 [2] 44 ec [2] 03 ee [2] 44 ff [2] 0a f3 [2] 06 f9 [2] 11 f2 [2] 0a bc [2] 37 }

  condition:
    any of them
}