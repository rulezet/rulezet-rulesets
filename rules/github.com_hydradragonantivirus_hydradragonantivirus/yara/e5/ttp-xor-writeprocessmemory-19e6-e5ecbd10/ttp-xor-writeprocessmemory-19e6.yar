rule TTP_XOR_WriteProcessMemory_19e6 {
  strings:
    $key_19e6 = { 4e 94 [2] 7c b6 [2] 7a 83 [2] 54 83 [2] 6b 9f }

  condition:
    any of them
}