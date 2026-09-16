rule TTP_XOR_WriteProcessMemory_ef43 {
  strings:
    $key_ef43 = { b8 31 [2] 8a 13 [2] 8c 26 [2] a2 26 [2] 9d 3a }

  condition:
    any of them
}