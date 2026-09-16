rule TTP_XOR_MULT_DOSStub_0728 {
  strings:
    $key_0728 = { 53 40 [2] 27 58 [2] 60 5a [2] 27 4b [2] 69 47 [2] 65 4d [2] 72 46 [2] 69 08 [2] 54 }

  condition:
    any of them
}