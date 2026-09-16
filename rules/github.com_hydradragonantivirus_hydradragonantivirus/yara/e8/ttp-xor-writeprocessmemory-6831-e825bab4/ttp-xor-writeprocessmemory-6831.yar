rule TTP_XOR_WriteProcessMemory_6831 {
  strings:
    $key_6831 = { 3f 43 [2] 0d 61 [2] 0b 54 [2] 25 54 [2] 1a 48 }

  condition:
    any of them
}