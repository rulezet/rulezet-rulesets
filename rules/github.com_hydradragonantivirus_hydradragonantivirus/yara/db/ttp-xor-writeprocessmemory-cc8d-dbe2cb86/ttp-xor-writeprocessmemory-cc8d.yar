rule TTP_XOR_WriteProcessMemory_cc8d {
  strings:
    $key_cc8d = { 9b ff [2] a9 dd [2] af e8 [2] 81 e8 [2] be f4 }

  condition:
    any of them
}