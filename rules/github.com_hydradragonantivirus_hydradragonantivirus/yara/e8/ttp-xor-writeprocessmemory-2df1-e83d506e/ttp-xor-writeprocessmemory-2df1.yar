rule TTP_XOR_WriteProcessMemory_2df1 {
  strings:
    $key_2df1 = { 7a 83 [2] 48 a1 [2] 4e 94 [2] 60 94 [2] 5f 88 }

  condition:
    any of them
}