rule TTP_XOR_MULT_DOSStub_fccc {
  strings:
    $key_fccc = { a8 a4 [2] dc bc [2] 9b be [2] dc af [2] 92 a3 [2] 9e a9 [2] 89 a2 [2] 92 ec [2] af }

  condition:
    any of them
}