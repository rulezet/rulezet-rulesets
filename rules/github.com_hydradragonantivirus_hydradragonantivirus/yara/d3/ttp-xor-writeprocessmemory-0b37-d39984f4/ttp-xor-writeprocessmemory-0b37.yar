rule TTP_XOR_WriteProcessMemory_0b37 {
  strings:
    $key_0b37 = { 5c 45 [2] 6e 67 [2] 68 52 [2] 46 52 [2] 79 4e }

  condition:
    any of them
}