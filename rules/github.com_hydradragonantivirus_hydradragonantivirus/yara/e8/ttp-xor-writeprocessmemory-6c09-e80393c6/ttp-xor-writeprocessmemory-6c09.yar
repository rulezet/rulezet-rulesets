rule TTP_XOR_WriteProcessMemory_6c09 {
  strings:
    $key_6c09 = { 3b 7b [2] 09 59 [2] 0f 6c [2] 21 6c [2] 1e 70 }

  condition:
    any of them
}