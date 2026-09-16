rule TTP_XOR_WriteProcessMemory_1b20 {
  strings:
    $key_1b20 = { 4c 52 [2] 7e 70 [2] 78 45 [2] 56 45 [2] 69 59 }

  condition:
    any of them
}