rule TTP_XOR_WriteProcessMemory_e9c7 {
  strings:
    $key_e9c7 = { be b5 [2] 8c 97 [2] 8a a2 [2] a4 a2 [2] 9b be }

  condition:
    any of them
}