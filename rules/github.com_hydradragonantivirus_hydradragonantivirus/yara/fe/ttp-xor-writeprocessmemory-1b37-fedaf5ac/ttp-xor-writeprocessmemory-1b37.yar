rule TTP_XOR_WriteProcessMemory_1b37 {
  strings:
    $key_1b37 = { 4c 45 [2] 7e 67 [2] 78 52 [2] 56 52 [2] 69 4e }

  condition:
    any of them
}