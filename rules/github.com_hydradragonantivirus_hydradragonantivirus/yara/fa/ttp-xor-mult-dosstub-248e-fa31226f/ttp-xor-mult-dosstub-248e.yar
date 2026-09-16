rule TTP_XOR_MULT_DOSStub_248e {
  strings:
    $key_248e = { 70 e6 [2] 04 fe [2] 43 fc [2] 04 ed [2] 4a e1 [2] 46 eb [2] 51 e0 [2] 4a ae [2] 77 }

  condition:
    any of them
}