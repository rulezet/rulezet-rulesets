rule TTP_XOR_WriteProcessMemory_5c0d {
  strings:
    $key_5c0d = { 0b 7f [2] 39 5d [2] 3f 68 [2] 11 68 [2] 2e 74 }

  condition:
    any of them
}