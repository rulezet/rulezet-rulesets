rule TTP_XOR_WriteProcessMemory_c903 {
  strings:
    $key_c903 = { 9e 71 [2] ac 53 [2] aa 66 [2] 84 66 [2] bb 7a }

  condition:
    any of them
}