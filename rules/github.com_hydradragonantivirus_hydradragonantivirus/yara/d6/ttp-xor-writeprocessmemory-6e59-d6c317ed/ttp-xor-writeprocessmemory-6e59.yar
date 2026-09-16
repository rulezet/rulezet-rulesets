rule TTP_XOR_WriteProcessMemory_6e59 {
  strings:
    $key_6e59 = { 39 2b [2] 0b 09 [2] 0d 3c [2] 23 3c [2] 1c 20 }

  condition:
    any of them
}