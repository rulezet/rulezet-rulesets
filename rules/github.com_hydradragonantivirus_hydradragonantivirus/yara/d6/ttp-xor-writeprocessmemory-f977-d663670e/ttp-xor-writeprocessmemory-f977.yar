rule TTP_XOR_WriteProcessMemory_f977 {
  strings:
    $key_f977 = { ae 05 [2] 9c 27 [2] 9a 12 [2] b4 12 [2] 8b 0e }

  condition:
    any of them
}