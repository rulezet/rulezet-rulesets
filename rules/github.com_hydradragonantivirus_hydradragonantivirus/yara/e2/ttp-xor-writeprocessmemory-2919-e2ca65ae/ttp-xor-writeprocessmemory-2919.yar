rule TTP_XOR_WriteProcessMemory_2919 {
  strings:
    $key_2919 = { 7e 6b [2] 4c 49 [2] 4a 7c [2] 64 7c [2] 5b 60 }

  condition:
    any of them
}