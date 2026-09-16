rule TTP_XOR_WriteProcessMemory_f9e0 {
  strings:
    $key_f9e0 = { ae 92 [2] 9c b0 [2] 9a 85 [2] b4 85 [2] 8b 99 }

  condition:
    any of them
}