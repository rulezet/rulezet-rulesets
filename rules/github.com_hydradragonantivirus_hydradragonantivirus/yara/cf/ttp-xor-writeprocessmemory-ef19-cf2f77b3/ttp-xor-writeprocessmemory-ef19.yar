rule TTP_XOR_WriteProcessMemory_ef19 {
  strings:
    $key_ef19 = { b8 6b [2] 8a 49 [2] 8c 7c [2] a2 7c [2] 9d 60 }

  condition:
    any of them
}