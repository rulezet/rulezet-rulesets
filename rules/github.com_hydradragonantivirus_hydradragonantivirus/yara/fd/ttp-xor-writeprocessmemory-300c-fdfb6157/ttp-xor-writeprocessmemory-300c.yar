rule TTP_XOR_WriteProcessMemory_300c {
  strings:
    $key_300c = { 67 7e [2] 55 5c [2] 53 69 [2] 7d 69 [2] 42 75 }

  condition:
    any of them
}