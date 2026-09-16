rule TTP_XOR_WriteProcessMemory_6bf2 {
  strings:
    $key_6bf2 = { 3c 80 [2] 0e a2 [2] 08 97 [2] 26 97 [2] 19 8b }

  condition:
    any of them
}