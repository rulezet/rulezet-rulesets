rule TTP_XOR_WriteProcessMemory_464a {
  strings:
    $key_464a = { 11 38 [2] 23 1a [2] 25 2f [2] 0b 2f [2] 34 33 }

  condition:
    any of them
}