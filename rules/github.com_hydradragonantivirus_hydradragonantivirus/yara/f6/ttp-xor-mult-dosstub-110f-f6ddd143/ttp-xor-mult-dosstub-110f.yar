rule TTP_XOR_MULT_DOSStub_110f {
  strings:
    $key_110f = { 45 67 [2] 31 7f [2] 76 7d [2] 31 6c [2] 7f 60 [2] 73 6a [2] 64 61 [2] 7f 2f [2] 42 }

  condition:
    any of them
}