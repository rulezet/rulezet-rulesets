rule TTP_XOR_WriteProcessMemory_da15 {
  strings:
    $key_da15 = { 8d 67 [2] bf 45 [2] b9 70 [2] 97 70 [2] a8 6c }

  condition:
    any of them
}