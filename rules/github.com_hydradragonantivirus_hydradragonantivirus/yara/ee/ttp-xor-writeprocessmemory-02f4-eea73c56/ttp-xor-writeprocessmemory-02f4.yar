rule TTP_XOR_WriteProcessMemory_02f4 {
  strings:
    $key_02f4 = { 55 86 [2] 67 a4 [2] 61 91 [2] 4f 91 [2] 70 8d }

  condition:
    any of them
}