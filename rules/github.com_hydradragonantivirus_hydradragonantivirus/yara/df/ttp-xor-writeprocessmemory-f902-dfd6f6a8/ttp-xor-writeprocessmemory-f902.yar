rule TTP_XOR_WriteProcessMemory_f902 {
  strings:
    $key_f902 = { ae 70 [2] 9c 52 [2] 9a 67 [2] b4 67 [2] 8b 7b }

  condition:
    any of them
}