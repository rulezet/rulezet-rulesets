rule TTP_XOR_WriteProcessMemory_2e59 {
  strings:
    $key_2e59 = { 79 2b [2] 4b 09 [2] 4d 3c [2] 63 3c [2] 5c 20 }

  condition:
    any of them
}