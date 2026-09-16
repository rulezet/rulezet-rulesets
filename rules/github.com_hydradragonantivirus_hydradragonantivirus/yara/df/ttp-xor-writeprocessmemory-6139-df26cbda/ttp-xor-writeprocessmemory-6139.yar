rule TTP_XOR_WriteProcessMemory_6139 {
  strings:
    $key_6139 = { 36 4b [2] 04 69 [2] 02 5c [2] 2c 5c [2] 13 40 }

  condition:
    any of them
}