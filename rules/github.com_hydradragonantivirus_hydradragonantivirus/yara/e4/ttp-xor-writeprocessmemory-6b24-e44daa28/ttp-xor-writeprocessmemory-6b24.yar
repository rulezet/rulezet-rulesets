rule TTP_XOR_WriteProcessMemory_6b24 {
  strings:
    $key_6b24 = { 3c 56 [2] 0e 74 [2] 08 41 [2] 26 41 [2] 19 5d }

  condition:
    any of them
}