rule TTP_XOR_WriteProcessMemory_e326 {
  strings:
    $key_e326 = { b4 54 [2] 86 76 [2] 80 43 [2] ae 43 [2] 91 5f }

  condition:
    any of them
}