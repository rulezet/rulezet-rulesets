rule TTP_XOR_WriteProcessMemory_f962 {
  strings:
    $key_f962 = { ae 10 [2] 9c 32 [2] 9a 07 [2] b4 07 [2] 8b 1b }

  condition:
    any of them
}