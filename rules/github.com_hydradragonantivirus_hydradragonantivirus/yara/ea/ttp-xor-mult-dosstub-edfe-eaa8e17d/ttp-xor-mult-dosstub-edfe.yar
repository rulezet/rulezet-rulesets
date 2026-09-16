rule TTP_XOR_MULT_DOSStub_edfe {
  strings:
    $key_edfe = { b9 96 [2] cd 8e [2] 8a 8c [2] cd 9d [2] 83 91 [2] 8f 9b [2] 98 90 [2] 83 de [2] be }

  condition:
    any of them
}