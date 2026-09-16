rule TTP_XOR_WriteProcessMemory_ef70 {
  strings:
    $key_ef70 = { b8 02 [2] 8a 20 [2] 8c 15 [2] a2 15 [2] 9d 09 }

  condition:
    any of them
}