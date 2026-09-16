rule TTP_XOR_WriteProcessMemory_8ca8 {
  strings:
    $key_8ca8 = { db da [2] e9 f8 [2] ef cd [2] c1 cd [2] fe d1 }

  condition:
    any of them
}