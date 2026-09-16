rule TTP_XOR_MULT_DOSStub_fcfe {
  strings:
    $key_fcfe = { a8 96 [2] dc 8e [2] 9b 8c [2] dc 9d [2] 92 91 [2] 9e 9b [2] 89 90 [2] 92 de [2] af }

  condition:
    any of them
}