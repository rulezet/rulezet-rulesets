rule TTP_XOR_WriteProcessMemory_1933 {
  strings:
    $key_1933 = { 4e 41 [2] 7c 63 [2] 7a 56 [2] 54 56 [2] 6b 4a }

  condition:
    any of them
}