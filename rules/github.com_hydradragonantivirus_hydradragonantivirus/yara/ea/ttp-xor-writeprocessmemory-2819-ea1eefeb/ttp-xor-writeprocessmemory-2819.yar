rule TTP_XOR_WriteProcessMemory_2819 {
  strings:
    $key_2819 = { 7f 6b [2] 4d 49 [2] 4b 7c [2] 65 7c [2] 5a 60 }

  condition:
    any of them
}