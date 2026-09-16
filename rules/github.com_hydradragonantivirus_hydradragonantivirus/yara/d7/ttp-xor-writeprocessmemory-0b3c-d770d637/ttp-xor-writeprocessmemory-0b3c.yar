rule TTP_XOR_WriteProcessMemory_0b3c {
  strings:
    $key_0b3c = { 5c 4e [2] 6e 6c [2] 68 59 [2] 46 59 [2] 79 45 }

  condition:
    any of them
}