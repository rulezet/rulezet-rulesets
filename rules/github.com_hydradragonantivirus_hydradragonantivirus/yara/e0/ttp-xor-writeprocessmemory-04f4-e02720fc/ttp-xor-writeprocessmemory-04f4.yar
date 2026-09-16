rule TTP_XOR_WriteProcessMemory_04f4 {
  strings:
    $key_04f4 = { 53 86 [2] 61 a4 [2] 67 91 [2] 49 91 [2] 76 8d }

  condition:
    any of them
}