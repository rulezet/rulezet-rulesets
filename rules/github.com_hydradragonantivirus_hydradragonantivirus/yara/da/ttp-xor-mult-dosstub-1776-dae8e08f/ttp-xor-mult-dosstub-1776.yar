rule TTP_XOR_MULT_DOSStub_1776 {
  strings:
    $key_1776 = { 43 1e [2] 37 06 [2] 70 04 [2] 37 15 [2] 79 19 [2] 75 13 [2] 62 18 [2] 79 56 [2] 44 }

  condition:
    any of them
}