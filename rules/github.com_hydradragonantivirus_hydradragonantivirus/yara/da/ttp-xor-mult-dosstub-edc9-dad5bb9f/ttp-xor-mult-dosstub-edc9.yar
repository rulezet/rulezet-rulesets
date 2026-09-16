rule TTP_XOR_MULT_DOSStub_edc9 {
  strings:
    $key_edc9 = { b9 a1 [2] cd b9 [2] 8a bb [2] cd aa [2] 83 a6 [2] 8f ac [2] 98 a7 [2] 83 e9 [2] be }

  condition:
    any of them
}