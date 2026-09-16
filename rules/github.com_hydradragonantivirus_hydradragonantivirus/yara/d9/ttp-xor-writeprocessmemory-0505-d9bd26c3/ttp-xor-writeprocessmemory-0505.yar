rule TTP_XOR_WriteProcessMemory_0505 {
  strings:
    $key_0505 = { 52 77 [2] 60 55 [2] 66 60 [2] 48 60 [2] 77 7c }

  condition:
    any of them
}