rule TTP_XOR_WriteProcessMemory_ef71 {
  strings:
    $key_ef71 = { b8 03 [2] 8a 21 [2] 8c 14 [2] a2 14 [2] 9d 08 }

  condition:
    any of them
}