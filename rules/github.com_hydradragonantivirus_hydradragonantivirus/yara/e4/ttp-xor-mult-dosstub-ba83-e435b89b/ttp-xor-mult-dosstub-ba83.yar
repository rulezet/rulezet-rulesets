rule TTP_XOR_MULT_DOSStub_ba83 {
  strings:
    $key_ba83 = { ee eb [2] 9a f3 [2] dd f1 [2] 9a e0 [2] d4 ec [2] d8 e6 [2] cf ed [2] d4 a3 [2] e9 }

  condition:
    any of them
}