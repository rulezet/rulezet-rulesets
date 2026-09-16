rule TTP_XOR_WriteProcessMemory_e3e4 {
  strings:
    $key_e3e4 = { b4 96 [2] 86 b4 [2] 80 81 [2] ae 81 [2] 91 9d }

  condition:
    any of them
}