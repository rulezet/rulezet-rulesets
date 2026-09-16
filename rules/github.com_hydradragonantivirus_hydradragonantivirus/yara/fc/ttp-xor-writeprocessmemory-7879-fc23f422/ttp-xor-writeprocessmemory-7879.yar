rule TTP_XOR_WriteProcessMemory_7879 {
  strings:
    $key_7879 = { 2f 0b [2] 1d 29 [2] 1b 1c [2] 35 1c [2] 0a 00 }

  condition:
    any of them
}