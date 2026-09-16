rule TTP_XOR_WriteProcessMemory_05f4 {
  strings:
    $key_05f4 = { 52 86 [2] 60 a4 [2] 66 91 [2] 48 91 [2] 77 8d }

  condition:
    any of them
}