rule TTP_XOR_WriteProcessMemory_6159 {
  strings:
    $key_6159 = { 36 2b [2] 04 09 [2] 02 3c [2] 2c 3c [2] 13 20 }

  condition:
    any of them
}