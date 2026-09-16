rule TTP_XOR_WriteProcessMemory_5a09 {
  strings:
    $key_5a09 = { 0d 7b [2] 3f 59 [2] 39 6c [2] 17 6c [2] 28 70 }

  condition:
    any of them
}