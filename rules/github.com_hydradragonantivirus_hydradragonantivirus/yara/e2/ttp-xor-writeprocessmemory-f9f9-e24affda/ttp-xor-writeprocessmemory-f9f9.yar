rule TTP_XOR_WriteProcessMemory_f9f9 {
  strings:
    $key_f9f9 = { ae 8b [2] 9c a9 [2] 9a 9c [2] b4 9c [2] 8b 80 }

  condition:
    any of them
}