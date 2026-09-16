rule TTP_XOR_WriteProcessMemory_e819 {
  strings:
    $key_e819 = { bf 6b [2] 8d 49 [2] 8b 7c [2] a5 7c [2] 9a 60 }

  condition:
    any of them
}