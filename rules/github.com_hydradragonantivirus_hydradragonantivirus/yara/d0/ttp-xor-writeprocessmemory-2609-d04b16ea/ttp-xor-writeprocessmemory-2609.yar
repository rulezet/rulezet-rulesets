rule TTP_XOR_WriteProcessMemory_2609 {
  strings:
    $key_2609 = { 71 7b [2] 43 59 [2] 45 6c [2] 6b 6c [2] 54 70 }

  condition:
    any of them
}