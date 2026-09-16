rule TTP_XOR_WriteProcessMemory_ef97 {
  strings:
    $key_ef97 = { b8 e5 [2] 8a c7 [2] 8c f2 [2] a2 f2 [2] 9d ee }

  condition:
    any of them
}