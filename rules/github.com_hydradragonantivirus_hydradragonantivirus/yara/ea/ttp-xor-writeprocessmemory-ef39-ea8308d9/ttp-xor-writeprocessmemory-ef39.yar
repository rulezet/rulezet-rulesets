rule TTP_XOR_WriteProcessMemory_ef39 {
  strings:
    $key_ef39 = { b8 4b [2] 8a 69 [2] 8c 5c [2] a2 5c [2] 9d 40 }

  condition:
    any of them
}