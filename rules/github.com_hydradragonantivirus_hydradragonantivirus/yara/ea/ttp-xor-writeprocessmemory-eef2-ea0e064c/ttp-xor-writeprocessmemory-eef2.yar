rule TTP_XOR_WriteProcessMemory_eef2 {
  strings:
    $key_eef2 = { b9 80 [2] 8b a2 [2] 8d 97 [2] a3 97 [2] 9c 8b }

  condition:
    any of them
}