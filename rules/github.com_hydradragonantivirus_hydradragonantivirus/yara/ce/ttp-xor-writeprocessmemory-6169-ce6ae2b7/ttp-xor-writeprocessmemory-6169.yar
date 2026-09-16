rule TTP_XOR_WriteProcessMemory_6169 {
  strings:
    $key_6169 = { 36 1b [2] 04 39 [2] 02 0c [2] 2c 0c [2] 13 10 }

  condition:
    any of them
}