rule TTP_XOR_WriteProcessMemory_da41 {
  strings:
    $key_da41 = { 8d 33 [2] bf 11 [2] b9 24 [2] 97 24 [2] a8 38 }

  condition:
    any of them
}