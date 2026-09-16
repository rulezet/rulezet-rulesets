rule TTP_XOR_WriteProcessMemory_e3e6 {
  strings:
    $key_e3e6 = { b4 94 [2] 86 b6 [2] 80 83 [2] ae 83 [2] 91 9f }

  condition:
    any of them
}