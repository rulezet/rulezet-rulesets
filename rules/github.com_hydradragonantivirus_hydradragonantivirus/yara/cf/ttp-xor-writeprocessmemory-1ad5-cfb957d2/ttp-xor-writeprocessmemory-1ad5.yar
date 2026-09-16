rule TTP_XOR_WriteProcessMemory_1ad5 {
  strings:
    $key_1ad5 = { 4d a7 [2] 7f 85 [2] 79 b0 [2] 57 b0 [2] 68 ac }

  condition:
    any of them
}