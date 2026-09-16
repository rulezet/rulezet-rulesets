rule TTP_XOR_WriteProcessMemory_0547 {
  strings:
    $key_0547 = { 52 35 [2] 60 17 [2] 66 22 [2] 48 22 [2] 77 3e }

  condition:
    any of them
}