rule TTP_XOR_WriteProcessMemory_0523 {
  strings:
    $key_0523 = { 52 51 [2] 60 73 [2] 66 46 [2] 48 46 [2] 77 5a }

  condition:
    any of them
}