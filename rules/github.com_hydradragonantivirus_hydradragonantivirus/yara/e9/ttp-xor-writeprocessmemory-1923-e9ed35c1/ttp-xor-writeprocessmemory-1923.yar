rule TTP_XOR_WriteProcessMemory_1923 {
  strings:
    $key_1923 = { 4e 51 [2] 7c 73 [2] 7a 46 [2] 54 46 [2] 6b 5a }

  condition:
    any of them
}