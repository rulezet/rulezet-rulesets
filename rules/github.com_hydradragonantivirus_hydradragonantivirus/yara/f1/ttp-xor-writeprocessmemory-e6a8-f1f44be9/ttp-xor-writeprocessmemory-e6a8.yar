rule TTP_XOR_WriteProcessMemory_e6a8 {
  strings:
    $key_e6a8 = { b1 da [2] 83 f8 [2] 85 cd [2] ab cd [2] 94 d1 }

  condition:
    any of them
}