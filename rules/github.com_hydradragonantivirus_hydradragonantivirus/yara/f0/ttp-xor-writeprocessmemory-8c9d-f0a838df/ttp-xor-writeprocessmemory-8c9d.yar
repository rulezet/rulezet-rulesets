rule TTP_XOR_WriteProcessMemory_8c9d {
  strings:
    $key_8c9d = { db ef [2] e9 cd [2] ef f8 [2] c1 f8 [2] fe e4 }

  condition:
    any of them
}