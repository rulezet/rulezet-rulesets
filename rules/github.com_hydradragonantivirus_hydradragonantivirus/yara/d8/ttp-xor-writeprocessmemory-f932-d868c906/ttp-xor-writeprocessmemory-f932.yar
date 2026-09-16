rule TTP_XOR_WriteProcessMemory_f932 {
  strings:
    $key_f932 = { ae 40 [2] 9c 62 [2] 9a 57 [2] b4 57 [2] 8b 4b }

  condition:
    any of them
}