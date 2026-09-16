rule TTP_XOR_WriteProcessMemory_380b {
  strings:
    $key_380b = { 6f 79 [2] 5d 5b [2] 5b 6e [2] 75 6e [2] 4a 72 }

  condition:
    any of them
}