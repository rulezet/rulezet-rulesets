rule TTP_XOR_WriteProcessMemory_f915 {
  strings:
    $key_f915 = { ae 67 [2] 9c 45 [2] 9a 70 [2] b4 70 [2] 8b 6c }

  condition:
    any of them
}