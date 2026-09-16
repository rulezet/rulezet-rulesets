rule TTP_XOR_WriteProcessMemory_3225 {
  strings:
    $key_3225 = { 65 57 [2] 57 75 [2] 51 40 [2] 7f 40 [2] 40 5c }

  condition:
    any of them
}