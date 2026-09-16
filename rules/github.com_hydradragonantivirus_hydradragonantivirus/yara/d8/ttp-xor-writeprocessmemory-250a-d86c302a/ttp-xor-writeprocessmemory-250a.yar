rule TTP_XOR_WriteProcessMemory_250a {
  strings:
    $key_250a = { 72 78 [2] 40 5a [2] 46 6f [2] 68 6f [2] 57 73 }

  condition:
    any of them
}