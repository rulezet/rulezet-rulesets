rule TTP_XOR_WriteProcessMemory_c909 {
  strings:
    $key_c909 = { 9e 7b [2] ac 59 [2] aa 6c [2] 84 6c [2] bb 70 }

  condition:
    any of them
}