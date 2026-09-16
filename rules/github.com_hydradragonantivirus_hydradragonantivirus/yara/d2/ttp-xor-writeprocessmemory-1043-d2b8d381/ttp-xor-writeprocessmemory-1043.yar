rule TTP_XOR_WriteProcessMemory_1043 {
  strings:
    $key_1043 = { 47 31 [2] 75 13 [2] 73 26 [2] 5d 26 [2] 62 3a }

  condition:
    any of them
}