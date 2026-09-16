rule TTP_XOR_WriteProcessMemory_1286 {
  strings:
    $key_1286 = { 45 f4 [2] 77 d6 [2] 71 e3 [2] 5f e3 [2] 60 ff }

  condition:
    any of them
}