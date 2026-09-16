rule TTP_XOR_WriteProcessMemory_1069 {
  strings:
    $key_1069 = { 47 1b [2] 75 39 [2] 73 0c [2] 5d 0c [2] 62 10 }

  condition:
    any of them
}