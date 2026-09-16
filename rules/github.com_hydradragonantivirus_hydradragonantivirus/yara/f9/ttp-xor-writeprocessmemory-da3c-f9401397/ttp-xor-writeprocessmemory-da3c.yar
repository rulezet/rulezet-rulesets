rule TTP_XOR_WriteProcessMemory_da3c {
  strings:
    $key_da3c = { 8d 4e [2] bf 6c [2] b9 59 [2] 97 59 [2] a8 45 }

  condition:
    any of them
}