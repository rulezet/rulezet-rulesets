rule TTP_XOR_WriteProcessMemory_3223 {
  strings:
    $key_3223 = { 65 51 [2] 57 73 [2] 51 46 [2] 7f 46 [2] 40 5a }

  condition:
    any of them
}