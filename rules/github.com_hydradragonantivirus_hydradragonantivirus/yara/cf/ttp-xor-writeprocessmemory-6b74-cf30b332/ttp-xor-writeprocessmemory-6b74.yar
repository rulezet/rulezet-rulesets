rule TTP_XOR_WriteProcessMemory_6b74 {
  strings:
    $key_6b74 = { 3c 06 [2] 0e 24 [2] 08 11 [2] 26 11 [2] 19 0d }

  condition:
    any of them
}