rule TTP_XOR_WriteProcessMemory_134a {
  strings:
    $key_134a = { 44 38 [2] 76 1a [2] 70 2f [2] 5e 2f [2] 61 33 }

  condition:
    any of them
}