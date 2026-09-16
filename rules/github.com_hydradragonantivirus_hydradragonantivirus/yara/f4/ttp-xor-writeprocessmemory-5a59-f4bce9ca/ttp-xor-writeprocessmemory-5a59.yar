rule TTP_XOR_WriteProcessMemory_5a59 {
  strings:
    $key_5a59 = { 0d 2b [2] 3f 09 [2] 39 3c [2] 17 3c [2] 28 20 }

  condition:
    any of them
}