rule TTP_XOR_WriteProcessMemory_150d {
  strings:
    $key_150d = { 42 7f [2] 70 5d [2] 76 68 [2] 58 68 [2] 67 74 }

  condition:
    any of them
}