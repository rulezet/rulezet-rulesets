rule TTP_XOR_WriteProcessMemory_383c {
  strings:
    $key_383c = { 6f 4e [2] 5d 6c [2] 5b 59 [2] 75 59 [2] 4a 45 }

  condition:
    any of them
}