rule TTP_XOR_WriteProcessMemory_6f09 {
  strings:
    $key_6f09 = { 38 7b [2] 0a 59 [2] 0c 6c [2] 22 6c [2] 1d 70 }

  condition:
    any of them
}