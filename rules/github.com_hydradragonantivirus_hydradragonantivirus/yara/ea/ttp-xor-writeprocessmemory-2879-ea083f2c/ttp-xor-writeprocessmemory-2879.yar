rule TTP_XOR_WriteProcessMemory_2879 {
  strings:
    $key_2879 = { 7f 0b [2] 4d 29 [2] 4b 1c [2] 65 1c [2] 5a 00 }

  condition:
    any of them
}