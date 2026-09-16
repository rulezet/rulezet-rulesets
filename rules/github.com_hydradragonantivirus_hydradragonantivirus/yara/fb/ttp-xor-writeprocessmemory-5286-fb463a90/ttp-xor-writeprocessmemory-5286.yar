rule TTP_XOR_WriteProcessMemory_5286 {
  strings:
    $key_5286 = { 05 f4 [2] 37 d6 [2] 31 e3 [2] 1f e3 [2] 20 ff }

  condition:
    any of them
}