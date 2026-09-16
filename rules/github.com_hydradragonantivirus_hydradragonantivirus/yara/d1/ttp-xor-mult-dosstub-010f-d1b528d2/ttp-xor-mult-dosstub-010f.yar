rule TTP_XOR_MULT_DOSStub_010f {
  strings:
    $key_010f = { 55 67 [2] 21 7f [2] 66 7d [2] 21 6c [2] 6f 60 [2] 63 6a [2] 74 61 [2] 6f 2f [2] 52 }

  condition:
    any of them
}