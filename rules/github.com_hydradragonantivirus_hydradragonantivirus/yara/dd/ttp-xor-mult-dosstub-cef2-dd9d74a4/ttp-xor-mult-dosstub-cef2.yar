rule TTP_XOR_MULT_DOSStub_cef2 {
  strings:
    $key_cef2 = { 9a 9a [2] ee 82 [2] a9 80 [2] ee 91 [2] a0 9d [2] ac 97 [2] bb 9c [2] a0 d2 [2] 9d }

  condition:
    any of them
}