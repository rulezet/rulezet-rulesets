rule TTP_XOR_WriteProcessMemory_7869 {
  strings:
    $key_7869 = { 2f 1b [2] 1d 39 [2] 1b 0c [2] 35 0c [2] 0a 10 }

  condition:
    any of them
}