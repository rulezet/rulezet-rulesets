rule TTP_XOR_WriteProcessMemory_05e5 {
  strings:
    $key_05e5 = { 52 97 [2] 60 b5 [2] 66 80 [2] 48 80 [2] 77 9c }

  condition:
    any of them
}