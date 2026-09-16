rule TTP_XOR_MULT_DOSStub_320f {
  strings:
    $key_320f = { 66 67 [2] 12 7f [2] 55 7d [2] 12 6c [2] 5c 60 [2] 50 6a [2] 47 61 [2] 5c 2f [2] 61 }

  condition:
    any of them
}