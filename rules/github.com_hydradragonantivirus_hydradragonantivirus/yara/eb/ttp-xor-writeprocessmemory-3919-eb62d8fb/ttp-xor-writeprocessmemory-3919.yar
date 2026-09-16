rule TTP_XOR_WriteProcessMemory_3919 {
  strings:
    $key_3919 = { 6e 6b [2] 5c 49 [2] 5a 7c [2] 74 7c [2] 4b 60 }

  condition:
    any of them
}