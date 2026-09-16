rule TTP_XOR_WriteProcessMemory_0697 {
  strings:
    $key_0697 = { 51 e5 [2] 63 c7 [2] 65 f2 [2] 4b f2 [2] 74 ee }

  condition:
    any of them
}