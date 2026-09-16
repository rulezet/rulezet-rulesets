rule TTP_XOR_WriteProcessMemory_ee45 {
  strings:
    $key_ee45 = { b9 37 [2] 8b 15 [2] 8d 20 [2] a3 20 [2] 9c 3c }

  condition:
    any of them
}