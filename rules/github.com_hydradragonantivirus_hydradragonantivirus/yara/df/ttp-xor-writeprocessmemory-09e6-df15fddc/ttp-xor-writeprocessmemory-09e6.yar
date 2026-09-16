rule TTP_XOR_WriteProcessMemory_09e6 {
  strings:
    $key_09e6 = { 5e 94 [2] 6c b6 [2] 6a 83 [2] 44 83 [2] 7b 9f }

  condition:
    any of them
}