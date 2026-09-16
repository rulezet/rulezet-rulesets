rule TTP_XOR_WriteProcessMemory_04e5 {
  strings:
    $key_04e5 = { 53 97 [2] 61 b5 [2] 67 80 [2] 49 80 [2] 76 9c }

  condition:
    any of them
}