rule TTP_XOR_WriteProcessMemory_2874 {
  strings:
    $key_2874 = { 7f 06 [2] 4d 24 [2] 4b 11 [2] 65 11 [2] 5a 0d }

  condition:
    any of them
}