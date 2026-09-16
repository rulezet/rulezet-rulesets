rule TTP_XOR_MULT_DOSStub_279c {
  strings:
    $key_279c = { 73 f4 [2] 07 ec [2] 40 ee [2] 07 ff [2] 49 f3 [2] 45 f9 [2] 52 f2 [2] 49 bc [2] 74 }

  condition:
    any of them
}