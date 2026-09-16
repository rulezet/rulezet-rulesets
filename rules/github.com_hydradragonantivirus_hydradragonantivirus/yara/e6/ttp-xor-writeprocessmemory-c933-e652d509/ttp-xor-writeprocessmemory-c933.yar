rule TTP_XOR_WriteProcessMemory_c933 {
  strings:
    $key_c933 = { 9e 41 [2] ac 63 [2] aa 56 [2] 84 56 [2] bb 4a }

  condition:
    any of them
}