rule TTP_XOR_WriteProcessMemory_3c39 {
  strings:
    $key_3c39 = { 6b 4b [2] 59 69 [2] 5f 5c [2] 71 5c [2] 4e 40 }

  condition:
    any of them
}