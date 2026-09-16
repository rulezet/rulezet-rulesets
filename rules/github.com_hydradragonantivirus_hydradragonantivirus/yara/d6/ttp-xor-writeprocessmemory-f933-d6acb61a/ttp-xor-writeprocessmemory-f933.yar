rule TTP_XOR_WriteProcessMemory_f933 {
  strings:
    $key_f933 = { ae 41 [2] 9c 63 [2] 9a 56 [2] b4 56 [2] 8b 4a }

  condition:
    any of them
}