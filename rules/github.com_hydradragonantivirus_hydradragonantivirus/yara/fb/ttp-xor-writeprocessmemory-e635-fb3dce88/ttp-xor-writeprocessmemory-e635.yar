rule TTP_XOR_WriteProcessMemory_e635 {
  strings:
    $key_e635 = { b1 47 [2] 83 65 [2] 85 50 [2] ab 50 [2] 94 4c }

  condition:
    any of them
}