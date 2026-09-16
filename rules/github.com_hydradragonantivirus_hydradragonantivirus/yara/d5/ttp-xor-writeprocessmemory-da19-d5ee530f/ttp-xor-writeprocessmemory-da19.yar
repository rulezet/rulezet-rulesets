rule TTP_XOR_WriteProcessMemory_da19 {
  strings:
    $key_da19 = { 8d 6b [2] bf 49 [2] b9 7c [2] 97 7c [2] a8 60 }

  condition:
    any of them
}