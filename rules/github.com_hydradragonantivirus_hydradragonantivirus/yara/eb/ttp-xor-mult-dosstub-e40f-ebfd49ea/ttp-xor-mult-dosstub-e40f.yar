rule TTP_XOR_MULT_DOSStub_e40f {
  strings:
    $key_e40f = { b0 67 [2] c4 7f [2] 83 7d [2] c4 6c [2] 8a 60 [2] 86 6a [2] 91 61 [2] 8a 2f [2] b7 }

  condition:
    any of them
}