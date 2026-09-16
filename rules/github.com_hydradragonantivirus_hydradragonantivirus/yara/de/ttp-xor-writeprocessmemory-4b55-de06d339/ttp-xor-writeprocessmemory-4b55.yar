rule TTP_XOR_WriteProcessMemory_4b55 {
  strings:
    $key_4b55 = { 1c 27 [2] 2e 05 [2] 28 30 [2] 06 30 [2] 39 2c }

  condition:
    any of them
}