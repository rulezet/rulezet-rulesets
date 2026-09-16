rule TTP_XOR_WriteProcessMemory_e609 {
  strings:
    $key_e609 = { b1 7b [2] 83 59 [2] 85 6c [2] ab 6c [2] 94 70 }

  condition:
    any of them
}