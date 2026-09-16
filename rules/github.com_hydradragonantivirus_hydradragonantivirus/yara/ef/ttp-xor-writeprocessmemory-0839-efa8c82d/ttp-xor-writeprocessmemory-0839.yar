rule TTP_XOR_WriteProcessMemory_0839 {
  strings:
    $key_0839 = { 5f 4b [2] 6d 69 [2] 6b 5c [2] 45 5c [2] 7a 40 }

  condition:
    any of them
}