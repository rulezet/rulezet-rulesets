rule TTP_XOR_MULT_DOSStub_5623 {
  strings:
    $key_5623 = { 02 4b [2] 76 53 [2] 31 51 [2] 76 40 [2] 38 4c [2] 34 46 [2] 23 4d [2] 38 03 [2] 05 }

  condition:
    any of them
}