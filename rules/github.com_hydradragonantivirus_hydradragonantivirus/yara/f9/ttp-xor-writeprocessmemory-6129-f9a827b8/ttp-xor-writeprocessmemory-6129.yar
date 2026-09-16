rule TTP_XOR_WriteProcessMemory_6129 {
  strings:
    $key_6129 = { 36 5b [2] 04 79 [2] 02 4c [2] 2c 4c [2] 13 50 }

  condition:
    any of them
}