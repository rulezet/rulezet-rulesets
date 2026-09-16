rule TTP_XOR_WriteProcessMemory_3209 {
  strings:
    $key_3209 = { 65 7b [2] 57 59 [2] 51 6c [2] 7f 6c [2] 40 70 }

  condition:
    any of them
}