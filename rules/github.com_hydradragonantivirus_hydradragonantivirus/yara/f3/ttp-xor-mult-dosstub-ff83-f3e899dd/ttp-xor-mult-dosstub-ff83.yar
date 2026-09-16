rule TTP_XOR_MULT_DOSStub_ff83 {
  strings:
    $key_ff83 = { ab eb [2] df f3 [2] 98 f1 [2] df e0 [2] 91 ec [2] 9d e6 [2] 8a ed [2] 91 a3 [2] ac }

  condition:
    any of them
}