rule TTP_XOR_MULT_DOSStub_e028 {
  strings:
    $key_e028 = { b4 40 [2] c0 58 [2] 87 5a [2] c0 4b [2] 8e 47 [2] 82 4d [2] 95 46 [2] 8e 08 [2] b3 }

  condition:
    any of them
}