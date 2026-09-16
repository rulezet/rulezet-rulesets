rule TTP_XOR_MULT_DOSStub_300f {
  strings:
    $key_300f = { 64 67 [2] 10 7f [2] 57 7d [2] 10 6c [2] 5e 60 [2] 52 6a [2] 45 61 [2] 5e 2f [2] 63 }

  condition:
    any of them
}