rule TTP_XOR_WriteProcessMemory_19e4 {
  strings:
    $key_19e4 = { 4e 96 [2] 7c b4 [2] 7a 81 [2] 54 81 [2] 6b 9d }

  condition:
    any of them
}