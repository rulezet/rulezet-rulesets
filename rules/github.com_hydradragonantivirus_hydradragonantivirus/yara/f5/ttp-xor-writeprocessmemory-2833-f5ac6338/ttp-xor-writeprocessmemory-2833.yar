rule TTP_XOR_WriteProcessMemory_2833 {
  strings:
    $key_2833 = { 7f 41 [2] 4d 63 [2] 4b 56 [2] 65 56 [2] 5a 4a }

  condition:
    any of them
}