rule TTP_XOR_WriteProcessMemory_2a2c {
  strings:
    $key_2a2c = { 7d 5e [2] 4f 7c [2] 49 49 [2] 67 49 [2] 58 55 }

  condition:
    any of them
}