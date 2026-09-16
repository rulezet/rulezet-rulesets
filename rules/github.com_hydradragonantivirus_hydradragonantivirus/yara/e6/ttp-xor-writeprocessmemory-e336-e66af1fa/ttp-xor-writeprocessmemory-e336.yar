rule TTP_XOR_WriteProcessMemory_e336 {
  strings:
    $key_e336 = { b4 44 [2] 86 66 [2] 80 53 [2] ae 53 [2] 91 4f }

  condition:
    any of them
}