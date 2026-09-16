rule TTP_XOR_WriteProcessMemory_6841 {
  strings:
    $key_6841 = { 3f 33 [2] 0d 11 [2] 0b 24 [2] 25 24 [2] 1a 38 }

  condition:
    any of them
}