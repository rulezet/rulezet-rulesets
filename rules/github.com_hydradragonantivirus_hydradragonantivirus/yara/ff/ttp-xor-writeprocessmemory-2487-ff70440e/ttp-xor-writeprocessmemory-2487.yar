rule TTP_XOR_WriteProcessMemory_2487 {
  strings:
    $key_2487 = { 73 f5 [2] 41 d7 [2] 47 e2 [2] 69 e2 [2] 56 fe }

  condition:
    any of them
}