rule TTP_XOR_WriteProcessMemory_6e3c {
  strings:
    $key_6e3c = { 39 4e [2] 0b 6c [2] 0d 59 [2] 23 59 [2] 1c 45 }

  condition:
    any of them
}