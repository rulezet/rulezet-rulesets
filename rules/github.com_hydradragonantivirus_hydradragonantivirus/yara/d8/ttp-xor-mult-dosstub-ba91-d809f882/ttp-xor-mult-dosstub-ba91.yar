rule TTP_XOR_MULT_DOSStub_ba91 {
  strings:
    $key_ba91 = { ee f9 [2] 9a e1 [2] dd e3 [2] 9a f2 [2] d4 fe [2] d8 f4 [2] cf ff [2] d4 b1 [2] e9 }

  condition:
    any of them
}