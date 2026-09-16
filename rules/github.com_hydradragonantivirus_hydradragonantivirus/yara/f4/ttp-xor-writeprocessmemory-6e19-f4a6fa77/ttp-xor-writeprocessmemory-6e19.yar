rule TTP_XOR_WriteProcessMemory_6e19 {
  strings:
    $key_6e19 = { 39 6b [2] 0b 49 [2] 0d 7c [2] 23 7c [2] 1c 60 }

  condition:
    any of them
}