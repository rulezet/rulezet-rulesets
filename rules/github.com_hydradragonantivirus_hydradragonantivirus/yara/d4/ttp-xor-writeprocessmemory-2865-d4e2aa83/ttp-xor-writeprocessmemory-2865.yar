rule TTP_XOR_WriteProcessMemory_2865 {
  strings:
    $key_2865 = { 7f 17 [2] 4d 35 [2] 4b 00 [2] 65 00 [2] 5a 1c }

  condition:
    any of them
}