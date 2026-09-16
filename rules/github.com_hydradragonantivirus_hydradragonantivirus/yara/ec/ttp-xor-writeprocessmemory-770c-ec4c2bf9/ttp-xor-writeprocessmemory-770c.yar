rule TTP_XOR_WriteProcessMemory_770c {
  strings:
    $key_770c = { 20 7e [2] 12 5c [2] 14 69 [2] 3a 69 [2] 05 75 }

  condition:
    any of them
}