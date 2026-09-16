rule TTP_XOR_WriteProcessMemory_c923 {
  strings:
    $key_c923 = { 9e 51 [2] ac 73 [2] aa 46 [2] 84 46 [2] bb 5a }

  condition:
    any of them
}