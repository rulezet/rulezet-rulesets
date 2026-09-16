rule TTP_XOR_WriteProcessMemory_342a {
  strings:
    $key_342a = { 63 58 [2] 51 7a [2] 57 4f [2] 79 4f [2] 46 53 }

  condition:
    any of them
}