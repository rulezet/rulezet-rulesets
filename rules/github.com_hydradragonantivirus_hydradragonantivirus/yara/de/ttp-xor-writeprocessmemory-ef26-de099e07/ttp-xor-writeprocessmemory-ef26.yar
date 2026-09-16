rule TTP_XOR_WriteProcessMemory_ef26 {
  strings:
    $key_ef26 = { b8 54 [2] 8a 76 [2] 8c 43 [2] a2 43 [2] 9d 5f }

  condition:
    any of them
}