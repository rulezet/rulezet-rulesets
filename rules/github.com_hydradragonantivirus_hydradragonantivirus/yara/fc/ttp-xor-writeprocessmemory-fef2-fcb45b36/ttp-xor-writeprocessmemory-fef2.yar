rule TTP_XOR_WriteProcessMemory_fef2 {
  strings:
    $key_fef2 = { a9 80 [2] 9b a2 [2] 9d 97 [2] b3 97 [2] 8c 8b }

  condition:
    any of them
}