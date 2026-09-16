rule TTP_XOR_WriteProcessMemory_4409 {
  strings:
    $key_4409 = { 13 7b [2] 21 59 [2] 27 6c [2] 09 6c [2] 36 70 }

  condition:
    any of them
}