rule TTP_XOR_WriteProcessMemory_daf2 {
  strings:
    $key_daf2 = { 8d 80 [2] bf a2 [2] b9 97 [2] 97 97 [2] a8 8b }

  condition:
    any of them
}