rule TTP_XOR_WriteProcessMemory_4b20 {
  strings:
    $key_4b20 = { 1c 52 [2] 2e 70 [2] 28 45 [2] 06 45 [2] 39 59 }

  condition:
    any of them
}