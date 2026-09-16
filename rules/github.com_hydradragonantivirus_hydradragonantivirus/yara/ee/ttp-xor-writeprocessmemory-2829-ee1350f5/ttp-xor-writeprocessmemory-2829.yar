rule TTP_XOR_WriteProcessMemory_2829 {
  strings:
    $key_2829 = { 7f 5b [2] 4d 79 [2] 4b 4c [2] 65 4c [2] 5a 50 }

  condition:
    any of them
}