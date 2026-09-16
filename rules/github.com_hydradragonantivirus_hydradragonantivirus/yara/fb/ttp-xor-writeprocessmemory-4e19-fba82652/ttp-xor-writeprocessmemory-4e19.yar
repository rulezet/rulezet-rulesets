rule TTP_XOR_WriteProcessMemory_4e19 {
  strings:
    $key_4e19 = { 19 6b [2] 2b 49 [2] 2d 7c [2] 03 7c [2] 3c 60 }

  condition:
    any of them
}