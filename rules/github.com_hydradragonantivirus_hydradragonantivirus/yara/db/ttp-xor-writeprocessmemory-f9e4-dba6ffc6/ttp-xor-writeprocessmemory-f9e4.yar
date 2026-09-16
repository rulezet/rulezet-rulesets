rule TTP_XOR_WriteProcessMemory_f9e4 {
  strings:
    $key_f9e4 = { ae 96 [2] 9c b4 [2] 9a 81 [2] b4 81 [2] 8b 9d }

  condition:
    any of them
}