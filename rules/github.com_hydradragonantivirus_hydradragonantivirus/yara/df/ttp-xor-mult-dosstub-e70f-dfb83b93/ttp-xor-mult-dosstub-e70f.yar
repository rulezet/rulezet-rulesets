rule TTP_XOR_MULT_DOSStub_e70f {
  strings:
    $key_e70f = { b3 67 [2] c7 7f [2] 80 7d [2] c7 6c [2] 89 60 [2] 85 6a [2] 92 61 [2] 89 2f [2] b4 }

  condition:
    any of them
}