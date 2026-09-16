rule TTP_XOR_WriteProcessMemory_ef02 {
  strings:
    $key_ef02 = { b8 70 [2] 8a 52 [2] 8c 67 [2] a2 67 [2] 9d 7b }

  condition:
    any of them
}