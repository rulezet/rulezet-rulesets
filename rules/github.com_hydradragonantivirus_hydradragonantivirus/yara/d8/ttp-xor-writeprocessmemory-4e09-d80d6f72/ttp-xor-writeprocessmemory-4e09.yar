rule TTP_XOR_WriteProcessMemory_4e09 {
  strings:
    $key_4e09 = { 19 7b [2] 2b 59 [2] 2d 6c [2] 03 6c [2] 3c 70 }

  condition:
    any of them
}