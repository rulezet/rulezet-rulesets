rule TTP_XOR_WriteProcessMemory_c922 {
  strings:
    $key_c922 = { 9e 50 [2] ac 72 [2] aa 47 [2] 84 47 [2] bb 5b }

  condition:
    any of them
}