rule TTP_XOR_WriteProcessMemory_0415 {
  strings:
    $key_0415 = { 53 67 [2] 61 45 [2] 67 70 [2] 49 70 [2] 76 6c }

  condition:
    any of them
}