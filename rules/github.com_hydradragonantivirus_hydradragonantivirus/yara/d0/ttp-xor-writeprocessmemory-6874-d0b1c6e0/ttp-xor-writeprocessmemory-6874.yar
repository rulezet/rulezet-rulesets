rule TTP_XOR_WriteProcessMemory_6874 {
  strings:
    $key_6874 = { 3f 06 [2] 0d 24 [2] 0b 11 [2] 25 11 [2] 1a 0d }

  condition:
    any of them
}