rule TTP_XOR_WriteProcessMemory_3859 {
  strings:
    $key_3859 = { 6f 2b [2] 5d 09 [2] 5b 3c [2] 75 3c [2] 4a 20 }

  condition:
    any of them
}