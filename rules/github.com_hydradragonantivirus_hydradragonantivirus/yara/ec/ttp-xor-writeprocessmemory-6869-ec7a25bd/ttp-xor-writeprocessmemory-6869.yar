rule TTP_XOR_WriteProcessMemory_6869 {
  strings:
    $key_6869 = { 3f 1b [2] 0d 39 [2] 0b 0c [2] 25 0c [2] 1a 10 }

  condition:
    any of them
}