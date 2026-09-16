rule TTP_XOR_MULT_DOSStub_ffcc {
  strings:
    $key_ffcc = { ab a4 [2] df bc [2] 98 be [2] df af [2] 91 a3 [2] 9d a9 [2] 8a a2 [2] 91 ec [2] ac }

  condition:
    any of them
}